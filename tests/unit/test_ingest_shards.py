"""End-to-end regression coverage for bounded staging and conversion batches."""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from seclogx.case import Case
from seclogx.ingest.common import SourceSpec, StageStatus
from seclogx.ingest.evtx.discovery import DiscoveredFile
from seclogx.ingest.evtx.stage import stage_file
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.sniff import KIND_SYSLOG
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.staging import StagingWriter, staged_batches


def _event(record_id: int, message: str = "cmd.exe") -> dict:
    return {
        "event_record_id": record_id,
        "timestamp": "2026-01-01T00:00:00Z UTC",
        "data": json.dumps({"Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                "EventID": 1, "Level": 4, "EventRecordID": record_id,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}},
                "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "HOST",
            },
            "EventData": {"CommandLine": message},
        }}),
    }


def _fake_evtx(monkeypatch, records: list[dict], *, fail_after: bool = False):
    import seclogx.ingest.evtx.stage as stage_module

    class FakeParser:
        def __init__(self, path, **kwargs):
            pass

        def records(self):
            for row in reversed(records):
                rid = row["event_record_id"]
                yield {"event_record_id": rid, "data": f"<Event>{rid}</Event>"}

        def records_json(self):
            yield from records
            if fail_after:
                raise ValueError("corrupt trailing EVTX chunk")

    monkeypatch.setattr(stage_module, "PyEvtxParser", FakeParser)


@pytest.mark.parametrize("keep_staging", [True, False])
def test_aux_shards_import_every_row_and_preserve_provenance(tmp_path: Path, keep_staging):
    source = tmp_path / "auth.log"
    source.write_text("".join(
        f"<34>1 2026-01-01T00:00:00Z original-host sshd 123 - - Failed password {i}\n"
        for i in range(24)
    ), encoding="utf-8")
    options = IngestOptions(memory_limit="128MB", threads=1, staging_chunk_bytes=1100, flatten_batch_bytes=2200)
    case = Case.create("aux-shards", case_root=tmp_path / "cases")
    updates = []
    report = case.ingest([f"{source}:EVIDENCE"], workers=1, options=options,
                         keep_staging=keep_staging, on_progress=updates.append)
    staged = report.aux.staged_files[0]
    assert len(staged.chunks) > 2
    assert staged.record_count == report.aux.rows_written["syslog"] == 24
    assert sum(chunk.record_count for chunk in staged.chunks) == 24
    chunk_sizes = {chunk.path: chunk.size_bytes for chunk in staged.chunks}
    batches = list(staged_batches([staged], options.flatten_batch_bytes))
    assert len(batches) > 1
    assert sum(len(batch) for batch in batches) == len(staged.chunks)
    assert all(sum(chunk_sizes[item.ndjson_path] for item in batch) <= options.flatten_batch_bytes for batch in batches)
    assert all(Path(chunk.path).exists() == keep_staging for chunk in staged.chunks)
    assert bool(list(case.case_dir.rglob("*.gz"))) == keep_staging
    result = case.query("SELECT host, source_path, source_file, file_sha256, message, ingest_batch_id FROM syslog")
    assert len(result) == 24
    assert set(result["host"]) == {"EVIDENCE"}
    assert set(result["source_path"]) == {str(source)}
    assert set(result["source_file"]) == {"auth.log"}
    assert set(result["file_sha256"]) == {hashlib.sha256(source.read_bytes()).hexdigest()}
    assert set(result["ingest_batch_id"]) == {report.aux.batch_id}
    assert set(result["message"]) == {f"Failed password {i}" for i in range(24)}
    assert updates[-1]["rows_written"] == {"syslog": 24}
    assert len({snap["rows_written"].get("syslog", 0) for snap in updates}) > 2


@pytest.mark.parametrize("keep_staging", [True, False])
def test_evtx_shards_keep_raw_match_record_ids_and_clean_sqlite(tmp_path: Path, monkeypatch, keep_staging):
    records = [_event(i) for i in range(7)]
    _fake_evtx(monkeypatch, records)
    source = tmp_path / "Security.evtx"
    source.write_bytes(b"synthetic evtx")
    case = Case.create("evtx-shards", case_root=tmp_path / "cases")
    options = IngestOptions(memory_limit="128MB", threads=1, staging_chunk_bytes=1000, flatten_batch_bytes=1500)
    report = case.ingest([f"{source}:EVIDENCE"], workers=1, keep_raw=True,
                         keep_staging=keep_staging, options=options)
    staged = report.staged_files[0]
    assert len(staged.chunks) > 2
    assert report.records_staged == report.records_flattened == len(records)
    assert not list(case.case_dir.rglob("*.sqlite*"))
    assert all(Path(chunk.path).exists() == keep_staging for chunk in staged.chunks)
    result = case.query("SELECT record_id, raw_xml, source_path, file_sha256 FROM events ORDER BY record_id")
    assert list(result["record_id"]) == list(range(7))
    assert list(result["raw_xml"]) == [f"<Event>{i}</Event>" for i in range(7)]
    assert set(result["source_path"]) == {str(source)}
    assert set(result["file_sha256"]) == {hashlib.sha256(source.read_bytes()).hexdigest()}


def test_evtx_partial_parse_keeps_all_completed_shards(tmp_path: Path, monkeypatch):
    _fake_evtx(monkeypatch, [_event(i) for i in range(5)], fail_after=True)
    source = tmp_path / "corrupt.evtx"
    source.write_bytes(b"fake")
    staged = stage_file(DiscoveredFile(source, "HOST", 4), tmp_path / "staging", keep_raw=True,
                        options=IngestOptions(staging_chunk_bytes=900))
    assert staged.status == StageStatus.PARTIAL
    assert staged.record_count == 5
    assert "corrupt trailing" in staged.error_message
    assert not list(tmp_path.rglob("*.sqlite*"))
    rows = []
    for chunk in staged.chunks:
        with gzip.open(chunk.path, "rt", encoding="utf-8") as handle:
            rows.extend(json.loads(line) for line in handle)
    assert [row["event_record_id"] for row in rows] == list(range(5))


def test_aux_partial_parse_preserves_written_prefix(tmp_path: Path, monkeypatch):
    import seclogx.ingest.logsources.stage as stage_module

    source = tmp_path / "auth.log"
    source.write_text("log")

    def fail_after_rows(cf, *, emit):
        for i in range(5):
            emit({"host": cf.host, "message": f"message {i}"})
        raise ValueError("bad source suffix")

    monkeypatch.setattr(stage_module, "_parse", fail_after_rows)
    staged = stage_aux_file(ClassifiedFile(source, "HOST", source.stat().st_size, KIND_SYSLOG),
                            tmp_path / "staging", IngestOptions(staging_chunk_bytes=300))
    assert staged.status == StageStatus.PARTIAL
    assert staged.record_count == sum(chunk.record_count for chunk in staged.chunks) == 5
    assert len(staged.chunks) > 1


def test_scan_keeps_supported_text_files_larger_than_two_gib(tmp_path: Path, monkeypatch):
    import seclogx.ingest.scan as scan_module

    source = tmp_path / "huge.log"
    source.write_text("<34>1 2026-01-01T00:00:00Z host sshd 1 - - Failed password\n")
    huge_size = 3 * 1024**3
    fake_stat = SimpleNamespace(st_size=huge_size, st_dev=1, st_ino=1)
    monkeypatch.setattr(scan_module, "_walk_files", lambda root: iter([(source, fake_stat)]))
    scan = scan_module.scan_sources([SourceSpec(tmp_path, "HOST")])
    assert len(scan.aux_files) == 1
    assert scan.aux_files[0].kind == KIND_SYSLOG
    assert scan.aux_files[0].size_bytes == huge_size


def test_record_larger_than_shard_target_remains_indivisible(tmp_path: Path):
    writer = StagingWriter(tmp_path / "large.ndjson.gz", chunk_bytes=20)
    rows = [{"message": "x" * 100}, {"message": "short"}]
    with writer:
        for row in rows:
            writer.write(row)
    assert [chunk.record_count for chunk in writer.chunks] == [1, 1]
    assert writer.chunks[0].size_bytes > 20


def test_oversize_record_is_rejected_without_creating_empty_shard(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(StagingWriter, "max_record_bytes", 40)
    writer = StagingWriter(tmp_path / "too-big.ndjson.gz", chunk_bytes=20)
    with pytest.raises(ValueError, match="encoded log record exceeds"):
        with writer:
            writer.write({"message": "x" * 100})
    assert writer.record_count == 0
    assert writer.chunks == []
    assert not list(tmp_path.glob("*.gz"))


def test_record_below_writer_limit_can_be_flattened(tmp_path: Path, monkeypatch):
    _fake_evtx(monkeypatch, [_event(1, "x" * (17 * 1024 * 1024))])
    source = tmp_path / "large-record.evtx"
    source.write_bytes(b"fake")
    case = Case.create("large-record", case_root=tmp_path / "cases")
    report = case.ingest([str(source)], workers=1)
    assert report.records_flattened == 1
    assert case.query("SELECT length(event_data ->> 'CommandLine') AS n FROM events")["n"].iloc[0] == 17 * 1024 * 1024


def test_evtx_writer_close_failure_still_cleans_raw_index(tmp_path: Path, monkeypatch):
    _fake_evtx(monkeypatch, [_event(1)])
    source = tmp_path / "write-failure.evtx"
    source.write_bytes(b"fake")
    original_close = StagingWriter.close

    def close_then_fail(writer):
        original_close(writer)
        raise OSError("simulated disk flush failure")

    monkeypatch.setattr(StagingWriter, "close", close_then_fail)
    with pytest.raises(OSError, match="simulated disk flush failure"):
        stage_file(DiscoveredFile(source, "HOST", 4), tmp_path / "staging", keep_raw=True)
    assert not list(tmp_path.rglob("*.sqlite*"))


def test_evtx_raw_index_write_failure_is_not_reported_as_success(tmp_path: Path, monkeypatch):
    import seclogx.ingest.evtx.stage as stage_module

    _fake_evtx(monkeypatch, [_event(1)])
    source = tmp_path / "raw-failure.evtx"
    source.write_bytes(b"fake")
    real_connect = sqlite3.connect

    class FailingIndex:
        def __init__(self, path):
            self.connection = real_connect(path)

        def execute(self, sql, *args):
            if sql.startswith("INSERT"):
                raise sqlite3.OperationalError("simulated database or disk is full")
            return self.connection.execute(sql, *args)

        def close(self):
            self.connection.close()

    monkeypatch.setattr(stage_module.sqlite3, "connect", FailingIndex)
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        stage_file(DiscoveredFile(source, "HOST", 4), tmp_path / "staging", keep_raw=True)
    assert not list(tmp_path.rglob("*.sqlite*"))


def test_registry_adapter_streams_without_reading_whole_hive(tmp_path: Path, monkeypatch):
    from registry_hive_builder import build_hive
    from seclogx.ingest.logsources.parsers.registry import parse_registry_hive_file

    source = tmp_path / "SOFTWARE"
    source.write_bytes(build_hive("\\System32\\Config\\SOFTWARE"))
    expected, expected_ok, expected_errors = parse_registry_hive_file(source, "HOST")
    original_open = Path.open
    reads = []

    class BoundedReads:
        def __init__(self, file):
            self.file = file

        def read(self, size=-1):
            assert size >= 0, "registry adapter must not read the entire hive"
            reads.append(size)
            return self.file.read(size)

        def __getattr__(self, name):
            return getattr(self.file, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.file.close()

    def guarded_open(path, *args, **kwargs):
        file = original_open(path, *args, **kwargs)
        return BoundedReads(file) if path == source else file

    monkeypatch.setattr(Path, "open", guarded_open)
    emitted = []
    rows, ok, errors = parse_registry_hive_file(source, "HOST", emit=emitted.append)
    assert reads
    assert rows == []
    assert emitted == expected
    assert (ok, errors) == (expected_ok, expected_errors)
