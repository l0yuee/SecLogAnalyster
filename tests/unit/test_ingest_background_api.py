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

import pytest

from seclogx.case import Case
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.jobs import read_job_status, write_job_status


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


@pytest.mark.parametrize("options", [None, IngestOptions(
    memory_limit="256MB", threads=1, staging_chunk_bytes=1025, flatten_batch_bytes=4097,
), IngestOptions(
    memory_limit="256MB", threads=1, staging_chunk_bytes=1025, flatten_batch_bytes=4097, staging_format="arrow",
)])
def test_case_ingest_background_completes_and_status_is_queryable(tmp_path: Path, options):
    case_root = tmp_path / "cases"
    source = tmp_path / "evidence"
    _build_source_tree(source)

    c = Case.create("bgapi", case_root=case_root)
    job_id = c.ingest_background([str(source)], options=options)
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
    assert not list((c.case_dir / "staging_aux").rglob("*.arrow"))
    assert not list((c.case_dir / "staging_aux").rglob("*.ndjson.gz"))

    # job_status() with no job_id defaults to the most recently started job.
    assert c.job_status() == status

    df = c.query("SELECT count(*) AS n FROM syslog")
    assert df["n"].iloc[0] == 2


def test_case_job_status_returns_none_when_no_jobs(tmp_path: Path):
    c = Case.create("nobgjobs", case_root=tmp_path / "cases")
    assert c.job_status() is None
    assert c.job_status("no-such-job") is None
    assert c.list_jobs() == []


def test_background_preserves_resource_settings_at_byte_precision(tmp_path: Path, monkeypatch):
    import seclogx.case as case_module

    commands = []
    monkeypatch.setattr(case_module.subprocess, "Popen", lambda args, **kwargs: commands.append(args))
    c = Case.create("settings", case_root=tmp_path / "cases")
    options = IngestOptions(memory_limit="256MB", threads=1, staging_chunk_bytes=1025, flatten_batch_bytes=4097)
    c.ingest_background([str(tmp_path / "evidence")], workers=1, options=options)
    args = commands[0]
    expected = {
        "--workers": "1", "--memory-limit": "256MB", "--duckdb-threads": "1",
        "--staging-chunk-bytes": "1025", "--flatten-batch-bytes": "4097",
    }
    for flag, value in expected.items():
        assert args[args.index(flag) + 1] == value


def test_background_initial_snapshot_precedes_child_and_never_overwrites_done(tmp_path: Path, monkeypatch):
    import seclogx.case as case_module

    c = Case.create("fast-child", case_root=tmp_path / "cases")

    def finish_during_spawn(args, **kwargs):
        job_id = args[args.index("--_job-id") + 1]
        initial = read_job_status(c.case_dir, job_id)
        assert initial is not None
        assert initial["phase"] == "scanning"
        assert initial["started_at"]
        initial["phase"] = "done"
        write_job_status(c.case_dir, job_id, initial)

    monkeypatch.setattr(case_module.subprocess, "Popen", finish_during_spawn)
    job_id = c.ingest_background([str(tmp_path / "evidence")])
    assert c.job_status(job_id)["phase"] == "done"


def test_background_spawn_failure_is_recorded_as_failed(tmp_path: Path, monkeypatch):
    import seclogx.case as case_module

    c = Case.create("no-child", case_root=tmp_path / "cases")

    def fail_to_spawn(*args, **kwargs):
        raise OSError("simulated process creation failure")

    monkeypatch.setattr(case_module.subprocess, "Popen", fail_to_spawn)
    with pytest.raises(OSError, match="simulated process creation failure"):
        c.ingest_background([str(tmp_path / "evidence")])
    status = c.list_jobs()[0]
    assert status["phase"] == "failed"
    assert "simulated process creation failure" in status["error"]


@pytest.mark.parametrize("backend", ["auto", "python", "native"])
def test_background_passes_selected_parser_backend_to_child_cli(tmp_path: Path, monkeypatch, backend):
    import sys
    import seclogx.case as case_module

    commands = []
    monkeypatch.setattr(case_module.subprocess, "Popen", lambda args, **kwargs: commands.append(args))
    case = Case.create("parser-option", case_root=tmp_path / "cases")
    case.ingest_background([str(tmp_path / "evidence")], workers=1,
                           options=IngestOptions(staging_format="arrow", parser_backend=backend))
    assert len(commands) == 1
    args = commands[0]
    assert args[:4] == [sys.executable, "-m", "seclogx.cli.main", "ingest"]
    assert args.count("--parser-backend") == 1
    assert args[args.index("--parser-backend") + 1] == backend
    assert args[args.index("--staging-format") + 1] == "arrow"


def test_real_background_child_honors_strict_native_for_unsupported_format(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_text("<34>1 2026-09-18T00:00:00Z host app 12 - - supported by Python\n", encoding="utf-8")
    case = Case.create("strict-native", case_root=tmp_path / "cases")
    job_id = case.ingest_background([str(source)], workers=1,
                                    options=IngestOptions(staging_format="arrow", parser_backend="native"))
    status = _wait_for_terminal_status(case, job_id, timeout=30)
    # This does not require the optional extension. Losing the native option
    # between API and child CLI would make this supported syslog import pass.
    assert status["phase"] == "failed"
    assert "native parser unavailable" in status["error"]
    assert "unsupported format" in status["error"]
    assert not list((case.case_dir / "staging_aux").rglob("*.arrow"))
    assert not list((case.case_dir / "staging_aux").rglob("*.ndjson.gz"))
    assert not list((case.case_dir / "lake").rglob("*.parquet"))


def test_real_native_background_matches_foreground_for_every_query_column(tmp_path: Path):
    pytest.importorskip("seclogx._native_backend")
    from uuid import UUID
    import hashlib
    import pandas as pd

    from seclogx.ingest.logsources.schema import WEB_LOGS_COLUMNS

    source_dir = tmp_path / "evidence"
    source_dir.mkdir()
    sources = {
        "nginx_access.log": (
            '192.0.2.1 - alice [18/Sep/2026:08:12:34 +0800] "GET /中文?q=1 HTTP/1.1" 200 12 "-" "UA"\n'
            '192.0.2.2 - - [18/Sep/2026:08:12:35 +0000] "POST /second HTTP/1.1" 404 -\n'
        ),
        "iis.log": (
            "#Software: Microsoft Internet Information Services\n"
            "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes extra\n"
            "2026-09-18 08:12:34 192.0.2.3 GET /iis 0200 00012 文档\n"
            "2026-09-18 08:12:35 192.0.2.4 POST /last 404 - -\n"
        ),
    }
    hashes = {}
    for name, content in sources.items():
        path = source_dir / name
        path.write_text(content, encoding="utf-8")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    options = IngestOptions(staging_format="arrow", parser_backend="native",
                            memory_limit="256MB", threads=1, staging_chunk_bytes=1024)
    foreground = Case.create("foreground", case_root=tmp_path / "cases")
    progress = []
    report = foreground.ingest([str(source_dir)], workers=1, options=options, on_progress=progress.append)
    assert report.aux.rows_written == {"web_logs": 4}
    assert all(staged.parser_backend == "native" for staged in report.aux.staged_files)
    assert progress[-1]["phase"] == "done"
    assert progress[-1]["rows_written"] == {"web_logs": 4}

    background = Case.create("background", case_root=tmp_path / "cases")
    job_id = background.ingest_background([str(source_dir)], workers=1, options=options)
    status = _wait_for_terminal_status(background, job_id, timeout=30)
    assert status["phase"] == "done"
    assert status["files_ok"] == 2
    assert status["files_partial"] == status["files_failed"] == 0
    assert status["rows_written"] == {"web_logs": 4}
    assert status["sources"] == [str(source_dir)]
    assert not list((background.case_dir / "staging_aux").rglob("*.arrow"))

    columns = [name for name, _ in WEB_LOGS_COLUMNS]
    results = []
    for case in (foreground, background):
        with case:
            result = case.query("SELECT * FROM web_logs ORDER BY source_file, uri_stem")
        assert set(result.columns) == set(columns)
        result = result[columns].copy()
        batch_ids = list(result.ingest_batch_id.unique())
        assert len(batch_ids) == 1
        UUID(batch_ids[0])
        assert result.ingested_at.notna().all()
        assert result.ingested_at.nunique() == 1
        assert set(result.schema_version) == {1}
        for name, expected_hash in hashes.items():
            records = result[result.source_file == name]
            assert len(records) == 2
            assert set(records.file_sha256) == {expected_hash}
            assert set(records.source_path) == {str(source_dir / name)}
        result["ingest_batch_id"] = "<independent-ingest>"
        result["ingested_at"] = pd.Timestamp("2000-01-01")
        results.append(result)
    pd.testing.assert_frame_equal(results[0], results[1])
