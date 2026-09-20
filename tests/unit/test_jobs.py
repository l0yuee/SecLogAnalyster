from __future__ import annotations

import time
import errno
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

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


def _windows_sharing_error(code=32):
    error = PermissionError(errno.EACCES, "simulated Windows sharing conflict")
    error.winerror = code
    return error


@pytest.mark.parametrize("winerror", [5, 32, 33])
def test_terminal_progress_retries_transient_windows_readers(tmp_path: Path, monkeypatch, winerror):
    import seclogx.ingest.jobs as jobs_module

    write_job_status(tmp_path, "job1", {"phase": "flattening"})
    original_replace = jobs_module.os.replace
    attempts = []
    delays = []

    def replace_after_reader_releases(source, target):
        attempts.append(source)
        assert read_job_status(tmp_path, "job1")["phase"] == "flattening"
        if len(attempts) < 3:
            raise _windows_sharing_error(winerror)
        original_replace(source, target)

    monkeypatch.setattr(jobs_module.os, "replace", replace_after_reader_releases)
    monkeypatch.setattr(jobs_module.time, "sleep", delays.append)
    reporter = ProgressReporter(on_update=lambda snapshot: write_job_status(tmp_path, "job1", snapshot))
    reporter.finish()
    assert read_job_status(tmp_path, "job1")["phase"] == "done"
    assert len(attempts) == 3
    assert len(set(attempts)) == 1
    assert delays == [0.01, 0.02]
    assert not list((tmp_path / "jobs").glob("*.tmp"))


@pytest.mark.parametrize("transient_code", [False, True])
def test_permanent_status_failure_is_bounded_preserves_old_snapshot_and_cleans_temp(tmp_path: Path, monkeypatch, transient_code):
    import seclogx.ingest.jobs as jobs_module

    write_job_status(tmp_path, "job1", {"phase": "staging"})
    attempts = []
    delays = []
    error = _windows_sharing_error() if transient_code else OSError(errno.ENOSPC, "disk full")

    def fail_replace(source, target):
        attempts.append(source)
        raise error

    monkeypatch.setattr(jobs_module.os, "replace", fail_replace)
    monkeypatch.setattr(jobs_module.time, "sleep", delays.append)
    with pytest.raises(OSError) as raised:
        write_job_status(tmp_path, "job1", {"phase": "done"})
    assert raised.value is error
    assert len(attempts) == (10 if transient_code else 1)
    assert sum(delays) < 0.7
    assert read_job_status(tmp_path, "job1")["phase"] == "staging"
    assert not list((tmp_path / "jobs").glob("*.tmp"))


def test_overlapping_status_writers_use_independent_temporary_files(tmp_path: Path, monkeypatch):
    import seclogx.ingest.jobs as jobs_module

    original_replace = jobs_module.os.replace
    temporary_paths = []

    def overlapping_replace(source, target):
        temporary_paths.append(source)
        if len(temporary_paths) == 1:
            # Complete another writer while the first snapshot awaits its
            # rename. A fixed job1.json.tmp would be consumed by this write.
            write_job_status(tmp_path, "job1", {"writer": "inner"})
            assert json.loads(Path(source).read_text(encoding="utf-8")) == {"writer": "outer"}
        original_replace(source, target)

    monkeypatch.setattr(jobs_module.os, "replace", overlapping_replace)
    write_job_status(tmp_path, "job1", {"writer": "outer"})
    assert len(set(temporary_paths)) == 2
    assert read_job_status(tmp_path, "job1") == {"writer": "outer"}
    assert not list((tmp_path / "jobs").glob("*.tmp"))


def test_status_write_failure_closes_and_removes_temporary_file(tmp_path: Path, monkeypatch):
    import seclogx.ingest.jobs as jobs_module

    write_job_status(tmp_path, "job1", {"phase": "staging"})

    def disk_full(status, handle, **kwargs):
        handle.write('{"incomplete":')
        raise OSError(errno.ENOSPC, "disk full while writing snapshot")

    monkeypatch.setattr(jobs_module.json, "dump", disk_full)
    with pytest.raises(OSError, match="disk full while writing snapshot"):
        write_job_status(tmp_path, "job1", {"phase": "done"})
    assert read_job_status(tmp_path, "job1")["phase"] == "staging"
    assert not list((tmp_path / "jobs").glob("*.tmp"))
