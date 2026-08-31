from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.locking import LocalCaseLock, get_case_lock


def test_local_case_lock_serializes_concurrent_critical_sections(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    overlap_detected = []
    active = 0
    counter_guard = threading.Lock()  # protects the `active` counter itself, not the thing under test

    def worker():
        nonlocal active
        with LocalCaseLock(case_dir):
            with counter_guard:
                active += 1
                if active > 1:
                    overlap_detected.append(True)
            time.sleep(0.05)
            with counter_guard:
                active -= 1

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not overlap_detected, "two threads held the case lock's critical section at the same time"


def test_get_case_lock_uses_local_when_not_distributed(tmp_path: Path):
    lock = get_case_lock(tmp_path, ClusterConfig.local())
    assert isinstance(lock, LocalCaseLock)


def test_concurrent_case_json_read_modify_write_survives_under_lock(tmp_path: Path):
    """Directly exercises the race Case.ingest() used to have before this
    module existed: two "writers" doing load -> mutate -> save without a
    lock lose one update (last write wins); with LocalCaseLock held
    around the whole cycle, every writer's update survives."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    meta_path = case_dir / "case.json"
    meta_path.write_text(json.dumps({"hosts": []}))

    def add_host(host: str) -> None:
        with LocalCaseLock(case_dir):
            meta = json.loads(meta_path.read_text())
            time.sleep(0.02)  # widen the race window a lock must close
            meta["hosts"] = sorted(set(meta["hosts"]) | {host})
            meta_path.write_text(json.dumps(meta))

    threads = [threading.Thread(target=add_host, args=(f"HOST{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = json.loads(meta_path.read_text())
    assert sorted(final["hosts"]) == sorted(f"HOST{i}" for i in range(8))
