"""End-to-end (real subprocess, no mocking) coverage of `seclogx ingest
--background` + `seclogx ingest-status`: the background job must survive
past the CLI invocation that spawned it, and its on-disk status must end
up matching what a synchronous foreground ingest of the same evidence
would have produced.
"""

from __future__ import annotations

import time
from pathlib import Path

from typer.testing import CliRunner

from seclogx.case import Case
from seclogx.cli.main import app
from seclogx.ingest.jobs import list_jobs, read_job_status

runner = CliRunner()


def _build_source_tree(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "auth.log").write_text(
        "<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password for invalid user admin\n"
        "<34>1 2026-01-01T00:00:01Z host01 sshd 123 - - Failed password for invalid user admin\n"
    )
    (root / "junk.bin").write_bytes(b"\x00" * 2048)


def _wait_for_terminal_status(case_dir: Path, job_id: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = read_job_status(case_dir, job_id)
        if status is not None and status.get("phase") in ("done", "failed"):
            return status
        time.sleep(0.2)
    raise AssertionError(f"background job {job_id} did not reach a terminal phase in time: {status}")


def test_background_ingest_completes_and_status_matches_foreground(tmp_path: Path):
    case_root = tmp_path / "cases"
    source = tmp_path / "evidence"
    _build_source_tree(source)

    result = runner.invoke(
        app, ["ingest", "bgcase", "--source", str(source), "--case-root", str(case_root), "--background"]
    )
    assert result.exit_code == 0, result.output
    assert "Started background ingest job" in result.output

    case_dir = case_root / "bgcase"
    jobs = list_jobs(case_dir)
    assert len(jobs) == 1
    job_id = jobs[0]["job_id"]

    status = _wait_for_terminal_status(case_dir, job_id)
    assert status["phase"] == "done"
    assert status["files_ok"] == 1
    assert status["files_unknown"] == 1
    assert status["rows_written"] == {"syslog": 2}
    # Fields the parent wrote before spawning must survive every
    # subsequent progress-driven overwrite of the status file.
    assert status["started_at"]
    assert status["sources"] == [str(source)]

    c = Case.open("bgcase", case_root=case_root)
    df = c.query("SELECT count(*) AS n FROM syslog")
    assert df["n"].iloc[0] == 2


def test_ingest_status_command_prints_job_status(tmp_path: Path):
    case_root = tmp_path / "cases"
    source = tmp_path / "evidence"
    _build_source_tree(source)

    runner.invoke(app, ["ingest", "bgcase2", "--source", str(source), "--case-root", str(case_root), "--background"])
    case_dir = case_root / "bgcase2"
    job_id = list_jobs(case_dir)[0]["job_id"]
    _wait_for_terminal_status(case_dir, job_id)

    result = runner.invoke(app, ["ingest-status", "bgcase2", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "phase=done" in result.output
    assert "syslog: 2" in result.output


def test_ingest_status_unknown_job_errors(tmp_path: Path):
    case_root = tmp_path / "cases"
    runner.invoke(app, ["case", "init", "empty", "--dir", str(case_root)])
    result = runner.invoke(app, ["ingest-status", "empty", "no-such-job", "--case-root", str(case_root)])
    assert result.exit_code != 0
