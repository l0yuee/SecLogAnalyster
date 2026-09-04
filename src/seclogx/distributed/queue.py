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
import time
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Callable

from ..errors import ClusterConfigError
from .config import ClusterConfig

INGEST_QUEUE_NAME = "seclogx-ingest"
HUNT_QUEUE_NAME = "seclogx-hunt"
DEFAULT_LOCAL_INGEST_WORKERS = min(8, os.cpu_count() or 1)


class JobQueue(ABC):
    @abstractmethod
    def submit_all(self, fn: Callable, args_list: list[tuple]) -> list[Any]:
        """Run `fn(*args)` for every `args` in `args_list` and return the
        results (order is not guaranteed to match `args_list` -- callers
        sort by their own key afterward, matching the pre-existing
        `as_completed`-based behavior)."""


class LocalJobQueue(JobQueue):
    def __init__(self, workers: int | None = None):
        self.workers = workers

    def submit_all(self, fn: Callable, args_list: list[tuple]) -> list[Any]:
        if not args_list:
            return []
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
        with ProcessPoolExecutor(max_workers=self.workers, mp_context=ctx) as pool:
            futures = [pool.submit(fn, *args) for args in args_list]
            for fut in as_completed(futures):
                results.append(fut.result())
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

    def submit_all(self, fn: Callable, args_list: list[tuple]) -> list[Any]:
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
                    results.append(job.return_value())
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
