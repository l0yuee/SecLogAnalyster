from __future__ import annotations

import os
import threading
import time

import pytest

from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.queue import (
    DEFAULT_LOCAL_INGEST_WORKERS,
    HUNT_QUEUE_NAME,
    LocalJobQueue,
    RQJobQueue,
    get_job_queue,
)

# Module-level and importable-by-name -- a hard requirement for any
# function dispatched through RQJobQueue (see queue.py's docstring);
# these double as the LocalJobQueue tasks below too.


def _add(a, b):
    return a + b


def _boom(*_args):
    raise ValueError("boom")


class TestLocalJobQueue:
    def test_runs_all_tasks_and_returns_results(self):
        queue = LocalJobQueue(workers=2)
        results = queue.submit_all(_add, [(1, 2), (3, 4), (5, 6)])
        assert sorted(results) == [3, 7, 11]

    def test_empty_args_list_returns_empty(self):
        assert LocalJobQueue().submit_all(_add, []) == []

    def test_default_ingest_worker_count_is_bounded(self):
        queue = get_job_queue(ClusterConfig.local())
        assert queue.workers == DEFAULT_LOCAL_INGEST_WORKERS
        assert 1 <= DEFAULT_LOCAL_INGEST_WORKERS <= 8

    def test_hunting_keeps_executor_default_worker_count(self):
        assert get_job_queue(ClusterConfig.local(), queue_name=HUNT_QUEUE_NAME).workers is None

    def test_get_job_queue_returns_local_when_not_distributed(self):
        assert isinstance(get_job_queue(ClusterConfig.local()), LocalJobQueue)


class _NoTimeoutDeathPenalty:
    """RQ's default death-penalty implementation installs a SIGALRM
    handler, which only works in the main thread -- irrelevant in real
    deployments (`seclogx worker` is its own OS process, see
    cli/worker_cmd.py) but not in this in-process, fakeredis-backed test,
    where the worker runs on a background thread. A no-op stand-in avoids
    that without touching the code under test."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def rq_env(monkeypatch):
    """A fakeredis-backed RQ worker running on a background thread,
    consuming seclogx's ingest queue, plus `redis.from_url` patched so
    RQJobQueue("redis://fake") connects to that same fake instance.

    Repeated burst passes rather than one `work(burst=False)` call: a
    blocking listen loop can only be stopped from outside via a real
    signal, which doesn't apply to a background thread -- and a daemon
    thread that outlives the test keeps running after teardown, which is
    exactly the kind of lingering multi-threaded state `fork()`-based
    `ProcessPoolExecutor` (used by LocalJobQueue and every ingest test)
    can corrupt. Explicit stop+join in teardown guarantees this thread is
    gone before the next test runs.
    """
    fakeredis = pytest.importorskip("fakeredis")
    import redis
    from rq import SimpleWorker

    from seclogx.distributed.queue import INGEST_QUEUE_NAME

    conn = fakeredis.FakeStrictRedis()
    monkeypatch.setattr(redis, "from_url", lambda *_a, **_k: conn)

    class _NoSignalsWorker(SimpleWorker):
        death_penalty_class = _NoTimeoutDeathPenalty

        def _install_signal_handlers(self):
            pass  # not the main thread here -- irrelevant for a real `seclogx worker` process

    stop = threading.Event()

    def run_worker():
        worker = _NoSignalsWorker([INGEST_QUEUE_NAME], connection=conn)
        while not stop.is_set():
            worker.work(burst=True)
            stop.wait(0.02)

    t = threading.Thread(target=run_worker, daemon=True)
    t.start()
    time.sleep(0.05)  # let it complete its first (empty) burst pass
    yield conn
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive(), "rq_env's worker thread failed to stop -- would corrupt later ProcessPoolExecutor use"


class TestRQJobQueue:
    def test_submit_all_round_trips_through_fake_redis(self, rq_env):
        queue = RQJobQueue("redis://fake")
        results = queue.submit_all(_add, [(1, 2), (3, 4), (5, 6)])
        assert sorted(results) == [3, 7, 11]

    def test_empty_args_list_returns_empty_without_enqueueing(self, rq_env):
        queue = RQJobQueue("redis://fake")
        assert queue.submit_all(_add, []) == []

    def test_failed_job_raises_runtime_error(self, rq_env):
        queue = RQJobQueue("redis://fake")
        with pytest.raises(RuntimeError, match="failed"):
            queue.submit_all(_boom, [(1,)])

    def test_get_job_queue_returns_rq_when_broker_configured(self, rq_env):
        cfg = ClusterConfig(broker_url="redis://fake")
        assert isinstance(get_job_queue(cfg), RQJobQueue)


@pytest.mark.skipif(
    "SECLOGX_TEST_REDIS_URL" not in os.environ, reason="set SECLOGX_TEST_REDIS_URL to run against a real Redis"
)
class TestRQJobQueueRealRedis:
    def test_submit_all_against_real_redis(self):
        queue = RQJobQueue(os.environ["SECLOGX_TEST_REDIS_URL"])
        results = queue.submit_all(_add, [(10, 20), (1, 1)])
        assert sorted(results) == [2, 30]
