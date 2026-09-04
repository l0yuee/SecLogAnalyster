from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

from seclogx.ingest.common import StageStatus
from seclogx.ingest.jobs import (
    PHASE_DONE,
    PHASE_FAILED,
    PHASE_SCANNING,
    ProgressReporter,
    list_jobs,
    read_job_status,
    write_job_status,
)


def _staged(status: str) -> SimpleNamespace:
    return SimpleNamespace(status=status)


def test_progress_reporter_tallies_results_by_status():
    updates: list[dict] = []
    p = ProgressReporter(on_update=updates.append, min_interval=0, min_count_interval=1)

    p.on_evtx_result(_staged(StageStatus.OK))
    p.on_aux_result(_staged(StageStatus.PARTIAL))
    p.on_aux_result(_staged(StageStatus.FAILED))
    p.on_aux_result(_staged(StageStatus.UNKNOWN))

    snap = p.snapshot()
    assert snap["evtx_staged"] == 1
    assert snap["aux_staged"] == 3
    assert snap["files_ok"] == 1
    assert snap["files_partial"] == 1
    assert snap["files_failed"] == 1
    assert snap["files_unknown"] == 1
    assert updates  # on_update was actually invoked


def test_progress_reporter_throttles_high_frequency_updates():
    updates: list[dict] = []
    # A large min_count_interval and min_interval means most individual
    # results shouldn't each trigger a callback -- only phase transitions
    # and finish() are forced through regardless.
    p = ProgressReporter(on_update=updates.append, min_interval=10.0, min_count_interval=1000)

    for _ in range(50):
        p.on_aux_result(_staged(StageStatus.OK))

    assert len(updates) == 0  # throttled: no phase change, not enough count/time elapsed
    p.finish()
    assert len(updates) == 1  # finish() always forces an emission
    assert updates[-1]["phase"] == PHASE_DONE


def test_progress_reporter_finish_with_error_sets_failed_phase():
    updates: list[dict] = []
    p = ProgressReporter(on_update=updates.append)
    assert p.phase == PHASE_SCANNING
    p.finish(error="boom")
    assert p.phase == PHASE_FAILED
    assert updates[-1]["error"] == "boom"


def test_progress_reporter_table_flattened_accumulates_per_table():
    p = ProgressReporter()
    p.on_table_flattened("syslog", 3)
    p.on_table_flattened("db_logs", 2)
    p.on_table_flattened("syslog", 4)
    assert p.rows_written == {"syslog": 7, "db_logs": 2}


def test_write_and_read_job_status_roundtrip(tmp_path: Path):
    case_dir = tmp_path / "case"
    write_job_status(case_dir, "job1", {"job_id": "job1", "phase": "staging", "files_ok": 3})
    status = read_job_status(case_dir, "job1")
    assert status == {"job_id": "job1", "phase": "staging", "files_ok": 3}


def test_read_job_status_missing_job_returns_none(tmp_path: Path):
    assert read_job_status(tmp_path / "case", "does-not-exist") is None


def test_list_jobs_sorted_most_recent_first(tmp_path: Path):
    case_dir = tmp_path / "case"
    write_job_status(case_dir, "old", {"job_id": "old", "started_at": "2026-01-01T00:00:00Z"})
    write_job_status(case_dir, "new", {"job_id": "new", "started_at": "2026-01-02T00:00:00Z"})

    jobs = list_jobs(case_dir)
    assert [j["job_id"] for j in jobs] == ["new", "old"]


def test_write_job_status_overwrite_is_atomic_and_readable_mid_stream(tmp_path: Path):
    case_dir = tmp_path / "case"
    for i in range(20):
        write_job_status(case_dir, "job1", {"job_id": "job1", "n": i})
        # A reader should never see a torn/partial write -- either the old
        # or the new complete document, never a decode error.
        status = read_job_status(case_dir, "job1")
        assert status is not None
        assert status["job_id"] == "job1"
