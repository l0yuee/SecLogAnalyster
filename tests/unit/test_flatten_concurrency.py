from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from seclogx.case import Case
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.query import CaseDB


def _syslog_row(host: str, message: str) -> dict:
    return {
        "host": host,
        "time_created": "2026-01-01T00:00:00+00:00",
        "hostname": host,
        "app_name": "testapp",
        "message": message,
    }


def _write_ndjson(path: Path, rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return str(path)


def test_concurrent_flatten_calls_do_not_collide(tmp_path: Path):
    """Regression test for the collision risk flatten_table had before
    FILENAME_PATTERN '{uuid}' was added: COPY's default partitioned
    filenames gave no uniqueness guarantee across independent COPY
    invocations, so two concurrent flatten calls into the same host=
    partition (exactly what distributed ingest workers do) could
    overwrite each other's Parquet file. DuckDB can also race while creating
    that shared partition directory on Windows. Runs two flushes into the
    same initially-absent partition concurrently and confirms neither
    failure mode loses rows."""
    case = Case.create("concurrency", case_root=tmp_path / "cases")
    case_dir = case.case_dir

    batch_a = [_syslog_row("LAB01", f"batch-a-{i}") for i in range(5)]
    batch_b = [_syslog_row("LAB01", f"batch-b-{i}") for i in range(5)]
    ndjson_a = _write_ndjson(tmp_path / "staging" / "batch_a.ndjson", batch_a)
    ndjson_b = _write_ndjson(tmp_path / "staging" / "batch_b.ndjson", batch_b)

    errors: list[Exception] = []

    def run(ndjson_paths: list[str], batch_id: str) -> None:
        try:
            flatten_table(case_dir, "syslog", ndjson_paths, batch_id, datetime.now(timezone.utc))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [
        threading.Thread(target=run, args=([ndjson_a], "batch-a")),
        threading.Thread(target=run, args=([ndjson_b], "batch-b")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"flatten_table raised under concurrency: {errors}"

    partition_dir = case_dir / "lake" / "syslog" / "host=LAB01"
    parquet_files = list(partition_dir.glob("*.parquet"))
    assert len(parquet_files) == 2, f"expected one uniquely-named Parquet file per concurrent writer, got {parquet_files}"

    db = CaseDB(case_dir)
    df = db.table("syslog")
    assert len(df) == 10, "rows from both concurrent flatten calls should all be present, none overwritten"
    messages = set(df["message"])
    assert all(f"batch-a-{i}" in messages for i in range(5))
    assert all(f"batch-b-{i}" in messages for i in range(5))
