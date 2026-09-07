"""Distributable-task dispatch for the two ingest pipelines (and, for
Sigma hunting, a chunk of rules -- see `detect/hunt.py`).

`LocalJobQueue` reproduces exactly the `ProcessPoolExecutor` pattern both
`ingest/evtx/orchestrator.py` and `ingest/logsources/orchestrator.py`
used inline before this module existed -- the default, with zero
behavior change. `RQJobQueue` is the opt-in cluster path: each task is
enqueued onto a Redis-backed queue (via RQ) and consumed by `seclogx
worker` processes running anywhere with network access to this broker
and to the case's shared storage (see `storage.py`). Task functions
dispatched through either queue must be module-level, importable
functions -- both `stage_file` and `stage_aux_file` already are.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import time
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from typing import Any, Callable

from ..errors import ClusterConfigError, UnguardedMainError
from .config import ClusterConfig

INGEST_QUEUE_NAME = "seclogx-ingest"
HUNT_QUEUE_NAME = "seclogx-hunt"
DEFAULT_LOCAL_INGEST_WORKERS = min(8, os.cpu_count() or 1)


def _running_from_unguarded_script() -> bool:
    """Whether this process is a plain `python script.py` run, as opposed
    to an interactive session/notebook (no `__main__.__file__`) or an
    already-spawned child.

    A `spawn` worker re-imports the caller's `__main__` module. When that
    module runs the ingest at import time -- i.e. no
    `if __name__ == "__main__":` guard -- the child re-enters the ingest
    and Python kills the pool. Only a script *can* hit that; a REPL or
    notebook `__main__` has no file to re-import, so it never does."""
    main = sys.modules.get("__main__")
    return getattr(main, "__file__", None) is not None


def _unguarded_main_error(fn: Callable) -> UnguardedMainError | None:
    """The actionable error to raise in place of a bare
    `BrokenProcessPool`, or None if a missing `__main__` guard can't be the
    cause (leave the original exception alone in that case -- it's a real
    worker crash: OOM-killed, segfaulting parser, ...)."""
    if not _running_from_unguarded_script():
        return None
    return UnguardedMainError(
        f"parallel staging ({fn.__name__}) could not start worker processes. "
        "If you are calling this from a script, the ingest must run under an "
        "`if __name__ == \"__main__\":` guard:\n\n"
        "    if __name__ == \"__main__\":\n"
        "        report = case.ingest([...])\n\n"
        "Worker processes re-import your script, so without the guard each one "
        "re-runs the ingest instead of doing its share of the work. "
        "Alternatively pass workers=1 (or --workers 1) to stage in this process "
        "without a worker pool. Notebooks and the `seclogx` CLI are unaffected."
    )


class JobQueue(ABC):
    @abstractmethod
    def submit_all(
        self, fn: Callable, args_list: list[tuple], on_result: Callable[[Any], None] | None = None
    ) -> list[Any]:
        """Run `fn(*args)` for every `args` in `args_list` and return the
        results (order is not guaranteed to match `args_list` -- callers
        sort by their own key afterward, matching the pre-existing
        `as_completed`-based behavior). If given, `on_result` is called
        with each result as soon as it becomes available (for incremental
        progress reporting -- see `ingest.jobs.ProgressReporter`); it does
        not affect what's returned."""


class LocalJobQueue(JobQueue):
    def __init__(self, workers: int | None = None):
        self.workers = workers

    def submit_all(
        self, fn: Callable, args_list: list[tuple], on_result: Callable[[Any], None] | None = None
    ) -> list[Any]:
        if not args_list:
            return []

        # One task, or an explicit workers=1: a process pool can only cost
        # here (spawning a worker re-imports pandas/duckdb/evtx, which is
        # far more than one small file's parse). Running inline is also the
        # escape hatch UnguardedMainError points callers at, so it must not
        # itself need a worker process.
        if self.workers == 1 or len(args_list) == 1:
            results = []
            for args in args_list:
                result = fn(*args)
                results.append(result)
                if on_result is not None:
                    on_result(result)
            return results

        results = []
        # spawn, not the platform default (fork on Linux): forking a
        # process that has live background threads -- e.g. redis-py's
        # connection handling or botocore/cryptography's internal state,
        # both reachable once the 'cluster' extra is installed alongside
        # local/non-distributed use -- can silently crash the forked
        # child (BrokenProcessPool). spawn re-imports cleanly instead;
        # stage_file/stage_aux_file are already plain module-level,
        # picklable functions, so this is a drop-in swap.
        ctx = multiprocessing.get_context("spawn")
        try:
            with ProcessPoolExecutor(max_workers=self.workers, mp_context=ctx) as pool:
                futures = [pool.submit(fn, *args) for args in args_list]
                for fut in as_completed(futures):
                    result = fut.result()
                    results.append(result)
                    if on_result is not None:
                        on_result(result)
        except BrokenProcessPool as e:
            hint = _unguarded_main_error(fn)
            if hint is None:
                raise
            raise hint from e
        return results


class RQJobQueue(JobQueue):
    def __init__(self, broker_url: str, queue_name: str = INGEST_QUEUE_NAME, poll_interval: float = 0.5):
        try:
            import redis
            from rq import Queue
        except ImportError as e:  # pragma: no cover - exercised only when redis/rq missing
            raise ClusterConfigError(
                "SECLOGX_BROKER_URL requires the 'cluster' extra: pip install 'seclogx[cluster]'"
            ) from e
        self.redis_conn = redis.from_url(broker_url)
        self.queue = Queue(queue_name, connection=self.redis_conn)
        self.poll_interval = poll_interval

    def submit_all(
        self, fn: Callable, args_list: list[tuple], on_result: Callable[[Any], None] | None = None
    ) -> list[Any]:
        from rq.job import JobStatus

        if not args_list:
            return []
        pending = [self.queue.enqueue(fn, *args) for args in args_list]
        results: list[Any] = []
        while pending:
            still_pending = []
            for job in pending:
                job.refresh()
                status = job.get_status(refresh=False)
                if status == JobStatus.FINISHED:
                    result = job.return_value()
                    results.append(result)
                    if on_result is not None:
                        on_result(result)
                elif status in (JobStatus.FAILED, JobStatus.STOPPED, JobStatus.CANCELED):
                    latest = job.latest_result()
                    reason = latest.exc_string if latest else "unknown error"
                    raise RuntimeError(f"distributed job {job.id} ({fn.__name__}) failed: {reason}")
                else:
                    still_pending.append(job)
            pending = still_pending
            if pending:
                time.sleep(self.poll_interval)
        return results


def get_job_queue(
    cluster_config: ClusterConfig | None = None,
    workers: int | None = None,
    queue_name: str = INGEST_QUEUE_NAME,
) -> JobQueue:
    cluster_config = cluster_config or ClusterConfig.from_env()
    if cluster_config.is_distributed:
        return RQJobQueue(cluster_config.broker_url, queue_name=queue_name)
    if workers is None and queue_name == INGEST_QUEUE_NAME:
        # ProcessPoolExecutor otherwise defaults to as many as 32 workers.
        # Parser workers import pandas/DuckDB and concurrently read the same
        # evidence disk, so that default often consumes more RAM and produces
        # more I/O contention without improving throughput. Hunting retains
        # executor-default parallelism; explicit ``--workers`` stays authoritative.
        workers = DEFAULT_LOCAL_INGEST_WORKERS
    return LocalJobQueue(workers=workers)
