"""Coverage for the Python-API surface of background ingest --
`Case.ingest_background()` / `Case.job_status()` / `Case.list_jobs()` --
which is the library equivalent of `seclogx ingest --background` /
`seclogx ingest-status` covered by test_ingest_background_cli.py. Real
subprocess, no mocking: the job must survive past this call returning and
its on-disk status must match what a synchronous `c.ingest()` of the same
evidence would have produced.
"""

from __future__ import annotations

import time
from pathlib import Path

from seclogx.case import Case


def _build_source_tree(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "auth.log").write_text(
        "<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password for invalid user admin\n"
        "<34>1 2026-01-01T00:00:01Z host01 sshd 123 - - Failed password for invalid user admin\n"
    )
    (root / "junk.bin").write_bytes(b"\x00" * 2048)


def _wait_for_terminal_status(c: Case, job_id: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = c.job_status(job_id)
        if status is not None and status.get("phase") in ("done", "failed"):
            return status
        time.sleep(0.2)
    raise AssertionError(f"background job {job_id} did not reach a terminal phase in time: {status}")


def test_case_ingest_background_completes_and_status_is_queryable(tmp_path: Path):
    case_root = tmp_path / "cases"
    source = tmp_path / "evidence"
    _build_source_tree(source)

    c = Case.create("bgapi", case_root=case_root)
    job_id = c.ingest_background([str(source)])
    assert job_id

    # list_jobs() must see it immediately (the initial synchronous status
    # write happens before ingest_background() returns).
    jobs = c.list_jobs()
    assert len(jobs) == 1
    assert jobs[0]["job_id"] == job_id

    status = _wait_for_terminal_status(c, job_id)
    assert status["phase"] == "done"
    assert status["files_ok"] == 1
    assert status["files_unknown"] == 1
    assert status["rows_written"] == {"syslog": 2}
    assert status["started_at"]
    assert status["sources"] == [str(source)]

    # job_status() with no job_id defaults to the most recently started job.
    assert c.job_status() == status

    df = c.query("SELECT count(*) AS n FROM syslog")
    assert df["n"].iloc[0] == 2


def test_case_job_status_returns_none_when_no_jobs(tmp_path: Path):
    c = Case.create("nobgjobs", case_root=tmp_path / "cases")
    assert c.job_status() is None
    assert c.job_status("no-such-job") is None
    assert c.list_jobs() == []
