import dataclasses
import hashlib
from pathlib import Path

import duckdb
import pytest

from seclogx.ingest.common import SourceSpec, StageStatus
from seclogx.ingest.evtx.discovery import DiscoveredFile
from seclogx.ingest.evtx.flatten import flatten_case
from seclogx.ingest.evtx.stage import stage_file, _recover_records, _prepare_evtx
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.scan import scan_sources
from seclogx.ingest.staging import staged_batches


FIXTURE = Path(__file__).parents[1] / "fixtures" / "evtx" / "security-seven.evtx"


@pytest.mark.parametrize("keep_raw", [False, True])
@pytest.mark.parametrize("staging_format", ["ndjson", "arrow"])
def test_real_evtx_recovers_good_chunk_after_corrupt_chunk(tmp_path, keep_raw, staging_format):
    data = FIXTURE.read_bytes()
    corrupt = bytearray(data[4096:])
    corrupt[0] = ord("X")
    source = tmp_path / "damaged.evtx"
    source.write_bytes(data + corrupt + data[4096:])
    staged = stage_file(DiscoveredFile(source, "HOST", source.stat().st_size), tmp_path / "staging",
                        keep_raw, IngestOptions(staging_format=staging_format))
    assert staged.record_count == 14
    assert staged.status == StageStatus.PARTIAL
    assert staged.error_count >= 1
    assert staged.error_message
    written = sum(flatten_case(tmp_path / "case", batch, "batch", keep_raw=keep_raw)
                  for batch in staged_batches([staged], 256 * 1024 * 1024))
    assert written == 14
    with duckdb.connect() as con:
        rows = con.execute("SELECT record_id, raw_xml FROM read_parquet(?, hive_partitioning=true)",
                           [str(tmp_path / "case" / "lake" / "events" / "**" / "*.parquet")]).fetchall()
    assert sorted(r[0] for r in rows) == sorted(list(range(1, 8)) * 2)
    assert all(bool(row[1]) == keep_raw for row in rows)
    assert not list(tmp_path.rglob("*.sqlite*"))


def test_arrow_evtx_matches_ndjson_every_canonical_field(tmp_path):
    results = []
    for kind in ("arrow", "ndjson"):
        output = tmp_path / kind
        staged = stage_file(DiscoveredFile(FIXTURE, "HOST", FIXTURE.stat().st_size), output / "staging",
                            True, IngestOptions(staging_format=kind, staging_chunk_bytes=8000))
        assert staged.status == StageStatus.OK
        for batch in staged_batches([staged], 10000):
            flatten_case(output, batch, "same-batch", keep_raw=True)
        with duckdb.connect() as con:
            results.append(con.execute("SELECT * EXCLUDE (ingested_at) FROM read_parquet(?) ORDER BY record_id",
                                       [str(output / "lake" / "events" / "**" / "*.parquet")]).fetchall())
            assert {row[0] for row in con.execute("SELECT DISTINCT compression FROM parquet_metadata(?)",
                                                [str(output / "lake" / "events" / "**" / "*.parquet")]).fetchall()} == {"ZSTD"}
    assert results[0] == results[1]


def test_recovery_does_not_swallow_io_failure():
    def records():
        yield {"data": "ok"}
        raise OSError("source device disconnected")
    iterator = _recover_records(records(), 4096, lambda _: None)
    assert next(iterator) == {"data": "ok"}
    with pytest.raises(OSError, match="device disconnected"):
        next(iterator)


def test_nonadvancing_recovery_iterator_has_finite_guard():
    class Broken:
        def __next__(self):
            raise RuntimeError("broken iterator")
    errors = []
    with pytest.raises(RuntimeError, match="physical input bound"):
        list(_recover_records(Broken(), 4096, errors.append))
    assert len(errors) == 1024


def test_source_ansi_metadata_and_native_thread_budget(tmp_path, monkeypatch):
    import seclogx.ingest.evtx.stage as module
    calls = []
    real_parser = module.PyEvtxParser
    def parser(path, **kwargs):
        calls.append(kwargs)
        return real_parser(path, **kwargs)
    monkeypatch.setattr(module, "PyEvtxParser", parser)
    specs = [SourceSpec(FIXTURE, "HOST", "cp936"), SourceSpec(FIXTURE, "HOST"), SourceSpec(FIXTURE, "OTHER")]
    scan = scan_sources(specs)
    assert len(scan.evtx_files) == 3
    for file in scan.evtx_files:
        staged = stage_file(file, tmp_path / "staging", keep_raw=True)
        assert staged.ansi_codec == ("gbk" if file.ansi_codec else "windows-1252")
        assert staged.ansi_codec_source == ("source" if file.ansi_codec else "default")
    assert all(call["number_of_threads"] == 1 for call in calls)
    assert {call["ansi_codec"] for call in calls} == {"gbk", "windows-1252"}


def test_invalid_source_codec_rejected_before_scan():
    with pytest.raises(ValueError, match="unsupported EVTX ANSI codec"):
        SourceSpec(FIXTURE, ansi_codec="invalid")


def test_evtx_flatten_integrity_failure_preserves_staging(tmp_path):
    staged = stage_file(DiscoveredFile(FIXTURE, "HOST", FIXTURE.stat().st_size), tmp_path / "staging")
    wrong = dataclasses.replace(staged, record_count=8)
    with pytest.raises(RuntimeError, match="staged 8 records but wrote 7"):
        flatten_case(tmp_path / "case", [wrong], "batch")
    assert Path(staged.ndjson_path).is_file()


def test_header_audit_hashes_exact_source_and_uses_record_ordinals():
    digest, count, complete = _prepare_evtx(FIXTURE)
    assert digest == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert count == 7
    assert complete


def test_suppressed_native_record_error_cannot_report_ok(tmp_path, monkeypatch):
    import seclogx.ingest.evtx.stage as module
    real_parser = module.PyEvtxParser
    class DroppingParser:
        def __init__(self, path, **kwargs):
            self.parser = real_parser(path, **kwargs)
        def records_json(self):
            for record in self.parser.records_json():
                if record["event_record_id"] != 4:
                    yield record
    monkeypatch.setattr(module, "PyEvtxParser", DroppingParser)
    staged = stage_file(DiscoveredFile(FIXTURE, "HOST", FIXTURE.stat().st_size), tmp_path / "staging")
    assert staged.status == StageStatus.PARTIAL
    assert staged.record_count == 6
    assert staged.header_record_count == 7
    assert "header count mismatch" in staged.error_message


def test_source_changed_during_parser_run_is_fatal(tmp_path, monkeypatch):
    import seclogx.ingest.evtx.stage as module
    from seclogx.textdecode import SourceChangedError
    path = tmp_path / "mutable.evtx"
    path.write_bytes(FIXTURE.read_bytes())
    real_parser = module.PyEvtxParser
    class MutatingParser:
        def __init__(self, source, **kwargs):
            self.parser = real_parser(source, **kwargs)
        def records_json(self):
            yield from self.parser.records_json()
            with path.open("ab") as stream:
                stream.write(b"changed")
    monkeypatch.setattr(module, "PyEvtxParser", MutatingParser)
    with pytest.raises(SourceChangedError, match="changed while parsing"):
        stage_file(DiscoveredFile(path, "HOST", path.stat().st_size), tmp_path / "staging")


def test_evtx_automatically_selects_arrow_at_source_threshold(tmp_path, monkeypatch):
    import seclogx.ingest.evtx.stage as module
    source = DiscoveredFile(FIXTURE, "HOST", FIXTURE.stat().st_size)
    small = stage_file(source, tmp_path / "small")
    assert small.staging_format == "ndjson"
    monkeypatch.setattr(module, "_ARROW_THRESHOLD_BYTES", FIXTURE.stat().st_size)
    large = stage_file(source, tmp_path / "large")
    assert large.staging_format == "arrow"
    assert large.record_count == small.record_count == 7


def test_raw_xml_memory_failure_is_fatal_and_cleans_index(tmp_path, monkeypatch):
    import seclogx.ingest.evtx.stage as module
    class FailingParser:
        def __init__(self, path, **kwargs):
            pass
        def records(self):
            raise MemoryError("raw parser allocation failed")
    monkeypatch.setattr(module, "PyEvtxParser", FailingParser)
    with pytest.raises(MemoryError, match="allocation failed"):
        stage_file(DiscoveredFile(FIXTURE, "HOST", FIXTURE.stat().st_size), tmp_path / "staging", keep_raw=True)
    assert not list(tmp_path.rglob("*.sqlite*"))
