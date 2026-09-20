from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pytest

from seclogx import Case, IngestOptions
from seclogx.ingest.arrow_staging import ArrowStagingWriter, arrow_reader
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.ingest.logsources.schema import TABLES
from seclogx.ingest.staging import StagingWriter


def test_arrow_buffers_are_bounded_and_shards_keep_every_row(tmp_path):
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1024, ["message", "optional"])
    with writer:
        for i in range(100):
            writer.write({"message": f"{i}:" + "中文" * 50})
            assert writer._buffer_bytes < writer._batch_limit
    assert len(writer.chunks) > 2
    assert writer.record_count == sum(c.record_count for c in writer.chunks) == 100
    with arrow_reader([c.path for c in writer.chunks], writer.schema.names) as reader:
        rows = [row for batch in reader for row in batch.to_pylist()]
    assert [row["message"] for row in rows] == [f"{i}:" + "中文" * 50 for i in range(100)]
    assert all(row["optional"] is None for row in rows)
    # All maps must be released when the reader exits, also on Windows.
    for chunk in writer.chunks:
        Path(chunk.path).unlink()


@pytest.mark.parametrize("partitions", [None, [("证据 / A", "iis")]])
def test_arrow_and_ndjson_have_identical_canonical_values(tmp_path, partitions):
    rows = [
        {"host": "证据 / A", "log_type": "iis", "time_created": "2026-09-17T08:12:34.123456+08:00",
         "username": "2026-09-17T00:00:00.000000Z", "status": 200, "bytes_sent": 9223372036854775807,
         "extra": '{"code":"000123","null":null}', "uri_stem": "中文\\n\n/路径", "source_file": "input.log"},
        {"host": "证据 / A", "log_type": "iis", "time_created": "invalid", "status": "bad",
         "bytes_sent": 9223372036854775808, "username": "000001"},
        {"host": "证据 / A", "log_type": "iis", "time_created": "2026-09-17T12:00:00",
         "status": None, "bytes_sent": True, "username": "", "extra": None},
        {"host": "证据 / A", "log_type": "iis", "time_created": "2026-09-17T00:00:00+99:99",
         "status": "00123", "bytes_sent": 1.5, "username": False},
    ]
    results = []
    for fmt in ("ndjson", "arrow"):
        case = Case.create(fmt, case_root=tmp_path / "cases")
        columns = [col for col, _ in TABLES["web_logs"]["columns"]]
        writer = (ArrowStagingWriter(tmp_path / "data.arrow", 700, columns) if fmt == "arrow"
                  else StagingWriter(tmp_path / "data.ndjson.gz", 700))
        with writer:
            for row in rows:
                writer.write(row)
        count = flatten_table(case.case_dir, "web_logs", [c.path for c in writer.chunks], "fixed-batch",
                              datetime(2026, 9, 17, tzinfo=timezone.utc),
                              options=IngestOptions(memory_limit="128MB", threads=1), partition_rows=partitions)
        assert count == len(rows)
        with duckdb.connect() as con:
            data = con.execute("SELECT * FROM read_parquet(?) ORDER BY username NULLS FIRST",
                               [str(case.case_dir / "lake" / "web_logs" / "**" / "*.parquet")]).fetchall()
            types = con.description
        results.append((data, types))
    assert results[0] == results[1]


@pytest.mark.parametrize("keep_staging", [True, False])
def test_case_ingest_arrow_preserves_source_hash_and_counts(tmp_path, keep_staging):
    import hashlib
    source = tmp_path / "auth.log"
    source.write_text("".join(
        f"<34>1 2026-01-01T00:00:00Z origin sshd 123 - - message {i}\n" for i in range(50)
    ), encoding="utf-8")
    case = Case.create("arrow", case_root=tmp_path / "cases")
    report = case.ingest([str(source)], workers=1, keep_staging=keep_staging,
                         options=IngestOptions(staging_format="arrow", staging_chunk_bytes=1024,
                                               flatten_batch_bytes=2048, threads=1))
    staged = report.aux.staged_files[0]
    assert report.aux.rows_written == {"syslog": 50}
    assert staged.status == "ok"
    assert len(staged.chunks) > 1
    assert all(Path(c.path).suffix == ".arrow" and Path(c.path).exists() == keep_staging for c in staged.chunks)
    result = case.query("SELECT message, source_path, file_sha256 FROM syslog")
    assert set(result.message) == {f"message {i}" for i in range(50)}
    assert set(result.source_path) == {str(source)}
    assert set(result.file_sha256) == {hashlib.sha256(source.read_bytes()).hexdigest()}


def test_arrow_rejects_oversize_record_without_losing_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 200)
    writer = ArrowStagingWriter(tmp_path / "data.arrow", 1000, ["message"])
    with pytest.raises(ValueError, match="encoded log record"):
        with writer:
            writer.write({"message": "good"})
            writer.write({"message": "x" * 300})
    assert writer.record_count == 1
    with arrow_reader([c.path for c in writer.chunks], ["message"]) as reader:
        assert reader.read_all().to_pylist() == [{"message": "good"}]


def test_arrow_write_failure_is_fatal_and_not_a_partial_source(tmp_path, monkeypatch):
    from seclogx.ingest.logsources.discovery import ClassifiedFile
    from seclogx.ingest.logsources.stage import stage_aux_file
    from seclogx.ingest.logsources.sniff import KIND_SYSLOG
    source = tmp_path / "auth.log"
    source.write_text("<34>1 2026-01-01T00:00:00Z origin sshd 123 - - message\n")

    def fail(self):
        raise RuntimeError("simulated Arrow writer failure")

    monkeypatch.setattr(ArrowStagingWriter, "_write_batch", fail)
    with pytest.raises(OSError, match="Arrow staging write failed"):
        stage_aux_file(ClassifiedFile(source, "H", source.stat().st_size, KIND_SYSLOG), tmp_path / "staging",
                       options=IngestOptions(staging_format="arrow"))
    assert not list((tmp_path / "staging").rglob("*.arrow"))


def test_staging_format_is_validated():
    with pytest.raises(ValueError, match="staging_format"):
        IngestOptions(staging_format="unexpected")


def test_auto_staging_converts_mixed_formats_in_one_case(tmp_path, monkeypatch):
    from seclogx.ingest.logsources import stage
    # Exercise the boundary with compact inputs; production threshold is 16 MiB.
    monkeypatch.setattr(stage, "AUTO_ARROW_MIN_BYTES", 200)
    small = tmp_path / "small.log"
    large = tmp_path / "large.log"
    line = "<34>1 2026-01-01T00:00:00Z origin sshd 123 - - message\n"
    small.write_text(line)
    large.write_text(line * 10)
    case = Case.create("mixed", case_root=tmp_path / "cases")
    # workers=1 runs the local queue in-process, keeping the test threshold.
    report = case.ingest([str(small), str(large)], workers=1, options=IngestOptions())
    assert report.aux.rows_written == {"syslog": 11}
    formats = {Path(f.source_path).name: Path(f.ndjson_path).suffix for f in report.aux.staged_files}
    assert formats == {"small.log": ".gz", "large.log": ".arrow"}
    assert case.query("SELECT count(*) AS n FROM syslog").iloc[0, 0] == 11
