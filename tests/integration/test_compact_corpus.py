"""Small, immutable source samples shared by local and CI product validation."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from seclogx import Case, IngestOptions
from seclogx.distributed.config import ClusterConfig
from seclogx.ingest.common import SourceSpec
from seclogx.ingest.logsources.sniff import classify_file
from seclogx.ingest.scan import scan_sources


CORPUS = Path(__file__).parents[1] / "fixtures" / "compact_corpus"
MANIFEST = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
FILES = MANIFEST["files"]
SUPPORTED = [item for item in FILES if item["scan_status"] == "supported"]
EXPECTED_ROWS = Counter()
for _item in SUPPORTED:
    EXPECTED_ROWS[_item["table"]] += _item["records"]


def test_sample_provenance_size_and_manifest_are_complete():
    assert MANIFEST["schema_version"] == 1
    assert MANIFEST["provenance"]["license"] == "MIT"
    assert MANIFEST["provenance"]["contains_real_evidence"] is False
    assert {item["format"] for item in SUPPORTED} == {
        "nginx", "iis", "syslog", "journal", "mysql_error", "exchange",
    }
    assert {item["format"] for item in FILES if item not in SUPPORTED} == {
        "elf", "pe", "pdf", "binary", "text",
    }
    actual = {path.relative_to(CORPUS).as_posix()
              for directory in ("valid", "noise")
              for path in (CORPUS / directory).rglob("*") if path.is_file()}
    assert actual == {item["path"] for item in FILES}
    assert sum(item["bytes"] for item in FILES) < 5 * 1024 * 1024


@pytest.mark.parametrize("item", FILES, ids=lambda item: item["path"])
def test_sample_bytes_and_content_classification(item):
    path = CORPUS / item["path"]
    payload = path.read_bytes()
    assert len(payload) == item["bytes"]
    assert hashlib.sha256(payload).hexdigest() == item["sha256"]
    assert classify_file(path) == item["kind"]
    if item["records"]:
        assert payload.endswith(b"\n")
        assert sum(bool(line.strip()) and not line.startswith(b"#")
                   for line in payload.splitlines()) == item["records"]


def test_mixed_source_discovery_accounts_for_noise():
    result = scan_sources([SourceSpec(CORPUS / "valid", "SAMPLE"),
                           SourceSpec(CORPUS / "noise", "SAMPLE")])
    assert result.evtx_files == []
    actual = {item.path.relative_to(CORPUS).as_posix(): item.kind
              for item in result.aux_files}
    expected = {item["path"]: item["kind"] for item in FILES
                if item["scan_status"] != "skipped_suffix"}
    assert actual == expected


def _ingest(case_root, name, options):
    case = Case.create(name, case_root=case_root, cluster_config=ClusterConfig.local())
    report = case.ingest([f"{CORPUS / 'valid'}:SAMPLE", f"{CORPUS / 'noise'}:SAMPLE"],
                         workers=1, options=options)
    assert report.aux.files_discovered == 9
    assert report.aux.files_ok == len(SUPPORTED)
    assert report.aux.files_unknown == 3
    assert report.aux.files_partial == report.aux.files_failed == 0
    assert report.aux.rows_written == dict(EXPECTED_ROWS)
    rows = {}
    with case:
        assert set(case.db.tables) == set(EXPECTED_ROWS)
        for table, expected_count in EXPECTED_ROWS.items():
            frame = case.query(f'SELECT * FROM "{table}" ORDER BY source_file, time_created')
            assert len(frame) == expected_count
            assert frame["time_created"].notna().all()
            assert str(frame["time_created"].dtype).startswith("datetime64")
            assert frame["host"].eq("SAMPLE").all()
            for item in SUPPORTED:
                if item["table"] == table:
                    source_rows = frame[frame["source_file"] == Path(item["path"]).name]
                    assert len(source_rows) == item["records"]
                    assert source_rows["file_sha256"].eq(item["sha256"]).all()
            # These two values describe the run, not the normalized evidence.
            rows[table] = frame.drop(columns=["ingest_batch_id", "ingested_at"], errors="ignore")
    return rows, report


@pytest.mark.parametrize("options", [
    IngestOptions(),
    IngestOptions(parser_backend="python", staging_format="arrow"),
    IngestOptions(parser_backend="auto", staging_format="arrow", direct_parquet=False),
], ids=["automatic", "python-arrow", "native-arrow"])
def test_complete_rows_match_python_reference(tmp_path, options):
    # Import the bundled component directly: a packaging mistake must fail CI.
    from seclogx import _native
    assert _native.API_VERSION == 1
    expected, _ = _ingest(tmp_path / "cases", "reference", IngestOptions(parser_backend="python"))
    actual, report = _ingest(tmp_path / "cases", "candidate", options)
    for table in expected:
        pd.testing.assert_frame_equal(actual[table], expected[table], check_exact=True)
    if options.parser_backend == "auto":
        web = [item for item in report.aux.staged_files if item.kind in {"web_access", "iis"}]
        assert len(web) == 2
        assert all(item.parser_backend == "native" for item in web)
