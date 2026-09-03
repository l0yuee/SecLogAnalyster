"""Coverage for gzip-compressed staged NDJSON: staged .evtx/aux records are
written as .ndjson.gz (see ingest/evtx/stage.py, ingest/logsources/stage.py)
to keep the case's staging directory from ballooning to several times the
source evidence size -- this checks the read side (flatten_case/
flatten_table, via DuckDB's read_ndjson/read_ndjson_auto) actually
understands the compressed files, and that aux staging skips hashing
files it never stages (unrecognized/binary content).
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

from seclogx.case import Case
from seclogx.ingest.evtx.flatten import flatten_case
from seclogx.ingest.evtx.manifest import StagedFile as EvtxStagedFile
from seclogx.ingest.evtx.manifest import now_iso
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.ingest.logsources.manifest import StageStatus
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.query import CaseDB


def _make_record(record_id: int) -> dict:
    """Record shaped like PyEvtxParser.records_json() output -- mirrors
    tests/conftest.py's make_record() (not importable here without a
    package __init__.py, and this test only needs a minimal shape)."""
    return {
        "event_record_id": record_id,
        "timestamp": "2026-01-01T00:00:00.000000Z UTC",
        "data": json.dumps(
            {
                "Event": {
                    "System": {
                        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                        "EventID": 1,
                        "Level": 4,
                        "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00.000000Z"}},
                        "EventRecordID": record_id,
                        "Channel": "Microsoft-Windows-Sysmon/Operational",
                        "Computer": "TESTHOST",
                    },
                    "EventData": {"Image": "cmd.exe"},
                }
            }
        ),
    }


def _write_gz_ndjson(path: Path, rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return str(path)


def test_flatten_case_reads_gzip_compressed_evtx_staging(tmp_path: Path):
    case = Case.create("gztest", case_root=tmp_path / "cases")
    records = [_make_record(i) for i in range(5)]
    ndjson_path = _write_gz_ndjson(tmp_path / "staging" / "fake.ndjson.gz", records)

    staged = EvtxStagedFile(
        source_path="/synthetic/fake.evtx",
        source_file="fake.evtx",
        host="TESTHOST",
        file_sha256="0" * 64,
        size_bytes=10,
        status="ok",
        record_count=len(records),
        error_count=0,
        error_message=None,
        ndjson_path=ndjson_path,
        staged_at=now_iso(),
    )
    row_count = flatten_case(case.case_dir, [staged], "testbatch")
    assert row_count == 5

    db = CaseDB(case.case_dir)
    assert len(db.table("events")) == 5


def test_flatten_table_reads_gzip_compressed_aux_staging(tmp_path: Path):
    case = Case.create("gztest2", case_root=tmp_path / "cases")
    rows = [
        {"host": "LAB01", "time_created": "2026-01-01T00:00:00+00:00", "hostname": "LAB01", "message": f"m{i}"}
        for i in range(5)
    ]
    ndjson_path = _write_gz_ndjson(tmp_path / "staging_aux" / "syslog.fake.ndjson.gz", rows)

    row_count = flatten_table(case.case_dir, "syslog", [ndjson_path], "testbatch", datetime.now(timezone.utc))
    assert row_count == 5

    db = CaseDB(case.case_dir)
    assert len(db.table("syslog")) == 5


def test_stage_aux_file_skips_hashing_unrecognized_content(tmp_path: Path):
    """A file that doesn't match any supported log format (e.g. a PE/ELF
    binary mixed into evidence) should be reported as unknown without
    ever being hashed or staged -- the hash isn't used for unknown files
    anywhere in the report, so computing it was pure wasted I/O on
    potentially large binary content."""
    junk = tmp_path / "some_binary_blob"
    junk.write_bytes(b"\x7fELF" + bytes(range(256)) * 4)

    cf = ClassifiedFile(path=junk, host="LAB01", size_bytes=junk.stat().st_size, kind=None)
    result = stage_aux_file(cf, tmp_path / "staging_aux")

    assert result.status == StageStatus.UNKNOWN
    assert result.file_sha256 == ""
    assert result.ndjson_path is None
