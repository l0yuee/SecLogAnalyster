"""Durable identity, liveness and cancellation, including real local processes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import psutil
import pytest
from typer.testing import CliRunner

from seclogx import Case
from seclogx.cli.main import app
from seclogx.distributed.locking import LocalCaseLock
from seclogx.ingest.common import SourceSpec, now_iso
from seclogx.ingest import job_control
from seclogx.ingest.jobs import job_log_path, job_status_path, read_job_status, write_job_status
from seclogx.ingest.persistence import atomic_json


def _initial(job_id="test-job", **values):
    return {"job_id": job_id, "phase": "staging", "started_at": now_iso(),
            "updated_at": now_iso(), "hostname": socket.gethostname(), **values}


def _wait(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("background condition did not become true")


@pytest.mark.parametrize("job_id", ["../case", "..", "/tmp/job", "C:\\job", "a/b", "a:b", "", "CON", "job.json"])
def test_job_ids_cannot_escape_status_directory(tmp_path, job_id):
    for operation in (job_status_path, job_log_path, read_job_status):
        with pytest.raises(ValueError, match="job ID"):
            operation(tmp_path, job_id)
    with pytest.raises(ValueError, match="job ID"):
        write_job_status(tmp_path, job_id, {})


def test_heartbeat_advances_without_progress_and_preserves_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(job_control, "HEARTBEAT_INTERVAL", 0.03)
    with job_control.JobHeartbeat(tmp_path, "test-job", _initial()) as heartbeat:
        first = read_job_status(tmp_path, "test-job")
        later = _wait(lambda: (value if (value := read_job_status(tmp_path, "test-job"))
                              and value["heartbeat_at"] != first["heartbeat_at"] else None))
        assert later["phase"] == "staging"
        assert later["pid"] == os.getpid()
        assert later["process_created_at"] == psutil.Process().create_time()
        heartbeat.update({"phase": "done"})
    assert read_job_status(tmp_path, "test-job")["phase"] == "done"


def test_reused_pid_is_interrupted_without_targeting_current_process(tmp_path):
    status = _initial(**job_control.process_identity())
    status["process_created_at"] += 100
    write_job_status(tmp_path, "test-job", status)
    assert job_control.owned_process(status) is None
    assert read_job_status(tmp_path, "test-job")["phase"] == "interrupted"
    assert job_control.cancel_job(tmp_path, "test-job")["phase"] == "interrupted"
    assert psutil.Process().is_running()


@pytest.mark.parametrize("invalid_time", [float("nan"), float("inf"), None, "not-a-time"])
def test_invalid_process_identity_is_never_owned(invalid_time):
    identity = {**job_control.process_identity(), "process_created_at": invalid_time}
    assert job_control.owned_process(identity) is None


def test_old_unregistered_job_reconciles_but_remote_job_does_not(tmp_path):
    old = _initial(started_at="2000-01-01T00:00:00+00:00", updated_at="2000-01-01T00:00:00+00:00")
    write_job_status(tmp_path, "test-job", old)
    assert read_job_status(tmp_path, "test-job")["phase"] == "interrupted"
    remote = {**old, "hostname": "another-host"}
    write_job_status(tmp_path, "test-job", remote)
    assert read_job_status(tmp_path, "test-job") == remote
    with pytest.raises(RuntimeError, match="host"):
        job_control.cancel_job(tmp_path, "test-job")


def test_committed_catalog_recovers_missing_terminal_status(tmp_path):
    status = _initial(pid=os.getpid(), process_created_at=0)
    write_job_status(tmp_path, "test-job", status)
    atomic_json(tmp_path / "case.json", {"ingest_runs": [{"job_id": "test-job"}]})
    recovered = read_job_status(tmp_path, "test-job")
    assert recovered["phase"] == "done"
    assert recovered["committed"] is True


def test_parent_identity_registration_never_overwrites_terminal_phase(tmp_path):
    write_job_status(tmp_path, "test-job", _initial(phase="done"))
    job_control.register_spawned_process(tmp_path, "test-job", os.getpid())
    status = read_job_status(tmp_path, "test-job")
    assert status["phase"] == "done"
    assert status["pid"] == os.getpid()


def test_cancel_before_child_registration_prevents_work(tmp_path):
    write_job_status(tmp_path, "test-job", _initial())
    assert job_control.cancel_job(tmp_path, "test-job")["phase"] == "cancelling"
    with pytest.raises(job_control.JobCancelledError):
        with job_control.JobHeartbeat(tmp_path, "test-job", _initial()):
            pytest.fail("cancelled child entered ingest")
    assert read_job_status(tmp_path, "test-job")["phase"] == "cancelled"


def test_cleanup_only_expires_terminal_logs_and_keeps_audit(tmp_path):
    case = Case.create("cleanup", case_root=tmp_path)
    write_job_status(case.case_dir, "finished", _initial("finished", phase="done"))
    write_job_status(case.case_dir, "running", _initial("running", **job_control.process_identity()))
    for job_id in ("finished", "running"):
        job_log_path(case.case_dir, job_id).write_text("console output", encoding="utf-8")
    result = case.cleanup_ingest(log_retention_days=0)
    assert result["log_paths"] == [str(job_log_path(case.case_dir, "finished"))]
    assert job_log_path(case.case_dir, "running").exists()
    assert job_status_path(case.case_dir, "finished").exists()
    with pytest.raises(ValueError):
        case.cleanup_ingest(log_retention_days=-1)


def test_background_source_metadata_preserves_each_ansi_codec(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr("seclogx.case.subprocess.Popen", lambda args, **kwargs: commands.append((args, kwargs)))
    case = Case.create("metadata", case_root=tmp_path)
    sources = [SourceSpec(tmp_path / "first.evtx", "CHINESE", "cp936"),
               SourceSpec(tmp_path / "second.evtx", "WESTERN", "cp1252")]
    case.ingest_background(sources)
    encoded = commands[0][1]["env"]["SECLOGX_SOURCE_SPECS"]
    assert [entry["ansi_codec"] for entry in json.loads(encoded)] == ["gbk", "windows-1252"]
    assert [entry["host"] for entry in json.loads(encoded)] == ["CHINESE", "WESTERN"]
    assert "SECLOGX_SOURCE_SPECS" not in os.environ


def test_cli_ansi_option_is_source_metadata(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr("seclogx.cli.ingest_cmd._run_in_foreground", lambda case, sources, *args: captured.extend(sources))
    result = CliRunner().invoke(app, ["ingest", "codec", "--source", str(tmp_path / "log.evtx"),
                                     "--evtx-ansi-codec", "cp936", "--case-root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured[0].ansi_codec == "gbk"


def test_real_blocked_cli_has_heartbeat_and_can_be_cancelled_then_retried(tmp_path):
    source = tmp_path / "access.log"
    source.write_text('192.0.2.1 - - [20/Sep/2026:12:34:56 +0000] "GET /retry HTTP/1.1" 200 10\n', encoding="utf-8")
    case = Case.create("blocked", case_root=tmp_path / "cases")
    job_id = None
    try:
        with LocalCaseLock(case.case_dir):
            job_id = case.ingest_background([str(source)], workers=1)
            first = _wait(lambda: (value if (value := case.job_status(job_id))
                                  and value.get("phase") == "flattening" else None))
            observed_at = time.monotonic()
            later = _wait(lambda: (value if (value := case.job_status(job_id))
                                  and value.get("heartbeat_at") != first["heartbeat_at"]
                                  and time.monotonic() - observed_at > job_control.HEARTBEAT_INTERVAL else None))
            assert later["phase"] == "flattening"
            cancelled = case.cancel_job(job_id)
            assert cancelled["phase"] == "cancelled"
            assert job_control.owned_process(cancelled) is None
        case.cleanup_ingest()
        assert case.ingest([str(source)], workers=1).aux.rows_written == {"web_logs": 1}
        with case:
            assert case.query("SELECT count(*) AS n FROM web_logs")["n"].iloc[0] == 1
    finally:
        if job_id:
            case.cancel_job(job_id)


_PROCESS_TREE = r'''
from pathlib import Path
import subprocess, sys, time
from seclogx.ingest.job_control import JobHeartbeat
case_dir, job_id = Path(sys.argv[1]), sys.argv[2]
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(45)"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with JobHeartbeat(case_dir, job_id, {"phase": "staging"}):
    time.sleep(45)
'''


@pytest.mark.parametrize("orphan", [False, True], ids=["live-tree", "orphan-worker"])
def test_cancel_terminates_real_worker_tree_after_parent_exit(tmp_path, orphan):
    case = Case.create("tree", case_root=tmp_path)
    job_id = "tree-job"
    process = subprocess.Popen([sys.executable, "-c", _PROCESS_TREE, str(case.case_dir), job_id, "seclogx.cli.main"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    identities = []
    try:
        status = _wait(lambda: (value if (value := case.job_status(job_id)) and value.get("children") else None))
        identities = status["children"]
        assert any(job_control.owned_process(identity) for identity in identities)
        if orphan:
            process.kill()
            process.wait(timeout=10)
            assert case.job_status(job_id)["phase"] == "interrupted"
        cancelled = case.cancel_job(job_id)
        assert cancelled["phase"] == "cancelled"
        process.wait(timeout=10)
        assert all(job_control.owned_process(identity) is None for identity in identities)
    finally:
        for identity in identities:
            if child := job_control.owned_process(identity):
                child.kill()
                child.wait(timeout=10)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


def test_cancel_finds_leased_orphan_missing_from_heartbeat(tmp_path):
    case = Case.create("lease", case_root=tmp_path)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(45)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        identity = job_control.process_identity(child.pid)
        workspace = case.case_dir / ".ingest" / "00000000-0000-0000-0000-000000000001"
        atomic_json(workspace / "state.json", {"job_id": "leased-job"})
        atomic_json(workspace / "workers" / "worker.json", identity)
        write_job_status(case.case_dir, "leased-job", _initial("leased-job", pid=os.getpid(), process_created_at=0, children=[]))
        assert case.job_status("leased-job")["workers_running"] == 1
        assert case.cancel_job("leased-job")["phase"] == "cancelled"
        child.wait(timeout=10)
        assert job_control.owned_process(identity) is None
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=10)
