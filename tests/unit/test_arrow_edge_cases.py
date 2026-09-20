"""Arrow staging must retain NDJSON value and failure-boundary semantics."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb
import pyarrow as pa
import pytest

from seclogx.ingest.arrow_staging import ArrowStagingWriter, arrow_reader
from seclogx.ingest.logsources import stage as stage_mod
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.sniff import KIND_SYSLOG
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.staging import StagingWriter


def _source(tmp_path: Path) -> ClassifiedFile:
    path = tmp_path / "source.log"
    path.write_text("<34>1 2026-01-01T00:00:00Z original app 12 - - safe\n", encoding="utf-8")
    return ClassifiedFile(path, "H", path.stat().st_size, KIND_SYSLOG)


def test_arrow_scalar_and_container_text_matches_ndjson(tmp_path):
    values = [
        None, False, True, 0, 2**64, 1.0, -0.0, 1e-7, 1e20,
        float("nan"), float("inf"), float("-inf"),
        {"text": "中文/\\\n", "nested": [False, None, 1.0]},
        ["中文", False, None, 1.0], datetime(2026, 1, 1, 1, 2, 3), b"raw\xff",
    ]
    ndjson = StagingWriter(tmp_path / "values.ndjson.gz", 1024 * 1024)
    arrow = ArrowStagingWriter(tmp_path / "values.arrow", 1024 * 1024, ["id", "value"])
    with ndjson, arrow:
        for index, value in enumerate(values):
            row = {"id": index, "value": value}
            ndjson.write(row)
            arrow.write(row)
    with duckdb.connect() as con:
        expected = con.execute(
            "SELECT id, value FROM read_ndjson(?, columns={'id':'VARCHAR','value':'VARCHAR'}) ORDER BY id::INT",
            [[chunk.path for chunk in ndjson.chunks]],
        ).fetchall()
        with arrow_reader([chunk.path for chunk in arrow.chunks], ["id", "value"]) as reader:
            con.register("values_arrow", reader)
            actual = con.execute("SELECT id, value FROM values_arrow ORDER BY id::INT").fetchall()
    assert actual == expected


@pytest.mark.parametrize("format", ["ndjson", "arrow"])
def test_json_control_character_expansion_obeys_same_record_limit(tmp_path, monkeypatch, format):
    monkeypatch.setattr(StagingWriter, "max_record_bytes", 16384)
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 16384)
    writer = (StagingWriter(tmp_path / "control.ndjson.gz", 65536) if format == "ndjson"
              else ArrowStagingWriter(tmp_path / "control.arrow", 65536, ["message"]))
    with pytest.raises(ValueError, match="encoded log record"):
        with writer:
            writer.write({"message": "\x00" * 3000})
    assert writer.record_count == 0


def test_arrow_footer_failure_is_fatal_instead_of_partial_manifest(tmp_path, monkeypatch):
    real_new_file = pa.ipc.new_file

    class FooterFailure:
        def __init__(self, *args, **kwargs):
            self.inner = real_new_file(*args, **kwargs)

        def write_batch(self, batch):
            self.inner.write_batch(batch)

        def close(self):
            self.inner.close()
            raise ValueError("injected footer failure")

    monkeypatch.setattr(pa.ipc, "new_file", FooterFailure)
    with pytest.raises(OSError):
        stage_mod.stage_aux_file(_source(tmp_path), tmp_path / "stage",
                                 options=IngestOptions(staging_format="arrow"))
    assert not list((tmp_path / "stage").rglob("*.arrow"))


def test_arrow_failure_after_batch_write_cannot_publish_a_successful_prefix(tmp_path, monkeypatch):
    real_write_batch = ArrowStagingWriter._write_batch
    failed = False

    def fail_once(self):
        nonlocal failed
        real_write_batch(self)
        if not failed and self._records:
            failed = True
            raise ValueError("injected post-write failure")

    monkeypatch.setattr(ArrowStagingWriter, "_write_batch", fail_once)
    with pytest.raises(OSError):
        stage_mod.stage_aux_file(_source(tmp_path), tmp_path / "stage",
                                 options=IngestOptions(staging_format="arrow", staging_chunk_bytes=1))
    assert not list((tmp_path / "stage").rglob("*.arrow"))


@pytest.mark.parametrize("during_rotation", [False, True], ids=["final-close", "rotation-close"])
def test_buffered_sink_close_failure_discards_current_and_completed_shards(tmp_path, monkeypatch, during_rotation):
    writers = []
    sinks = []
    opened_paths = []
    real_output_stream = pa.output_stream

    def capture_output_stream(path, **kwargs):
        opened_paths.append(path)
        return real_output_stream(path, **kwargs)

    def capture_writer(*args, **kwargs):
        writer = ArrowStagingWriter(*args, **kwargs)
        writers.append(writer)
        return writer

    class FlushFailure:
        """Leave the stream open on failure so cleanup must release its handle."""

        def __init__(self, inner):
            self.inner = inner
            self.close_calls = 0
            self.error = OSError("injected buffered flush failure")

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise self.error
            self.inner.close()

    def parse_two_shards(cf, *, emit):
        emit({"host": cf.host, "message": "completed-shard"})
        emit({"host": cf.host, "message": "pending-shard"})
        writer = writers[0]
        # A one-byte target rotates before the second record. Only its sink
        # is faulted: IPC footer writing itself continues to use the real sink.
        assert len(writer.chunks) == 1
        assert Path(writer.chunks[0].path).exists()
        failed_sink = FlushFailure(writer._sink)
        writer._sink = failed_sink
        sinks.append(failed_sink)
        if during_rotation:
            # Closing the second shard fails before this batch can be written.
            # __exit__ must clean up instead of reopening the same output path.
            emit({"host": cf.host, "message": "must-not-be-written"})
        return [], "syslog", 2, 0

    monkeypatch.setattr(pa, "output_stream", capture_output_stream)
    monkeypatch.setattr(stage_mod, "ArrowStagingWriter", capture_writer)
    monkeypatch.setattr(stage_mod, "_parse", parse_two_shards)
    try:
        with pytest.raises(OSError) as failure:
            stage_mod.stage_aux_file(
                _source(tmp_path), tmp_path / "stage",
                options=IngestOptions(staging_format="arrow", staging_chunk_bytes=1),
            )
    finally:
        # Release injected handles even if the regression returns, so a
        # failing test does not leave Windows temp-directory cleanup blocked.
        for sink in sinks:
            sink.closed_by_cleanup = sink.inner.closed
            sink.inner.close()

    # The accepted second record must never become a successful shard when
    # the stream flush fails. A source-level storage error is fatal and
    # removes the already completed prefix as well as the current output.
    assert [chunk.record_count for chunk in writers[0].chunks] == [1]
    assert sinks[0].close_calls >= 2
    assert sinks[0].closed_by_cleanup
    assert failure.value is sinks[0].error or failure.value.__cause__ is sinks[0].error
    assert len(opened_paths) == len(set(opened_paths)) == 2
    assert not list((tmp_path / "stage").rglob("*.arrow"))

    writer = writers[0]
    accepted_count = writer.record_count
    for _ in range(3):
        with pytest.raises(OSError, match="writer has failed"):
            writer.write({"message": "reject-without-buffering"})
    with pytest.raises(OSError):
        writer.close()
    assert writer.record_count == accepted_count
    assert writer._rows == []
    assert writer._buffer_bytes == 0
    assert len(opened_paths) == 2


def test_parse_failure_flushes_only_accepted_rows_and_keeps_manifest_counts(tmp_path, monkeypatch):
    def parse_prefix(cf, *, emit):
        emit({"host": cf.host, "message": "accepted-1"})
        emit({"host": cf.host, "message": "accepted-2"})
        raise ValueError("injected parse failure")

    monkeypatch.setattr(stage_mod, "_parse", parse_prefix)
    result = stage_mod.stage_aux_file(_source(tmp_path), tmp_path / "stage",
                                      options=IngestOptions(staging_format="arrow"))
    assert result.status == "partial"
    assert result.error_count == 1
    assert result.record_count == sum(chunk.record_count for chunk in result.chunks) == 2
    with pa.memory_map(result.chunks[0].path, "r") as source:
        rows = pa.ipc.open_file(source).read_all().to_pylist()
    assert [row["message"] for row in rows] == ["accepted-1", "accepted-2"]


@pytest.mark.parametrize("format", ["ndjson", "arrow"])
def test_unpaired_surrogate_is_a_partial_source_with_only_valid_prefix(tmp_path, monkeypatch, format):
    def parse_bad_text(cf, *, emit):
        emit({"host": cf.host, "message": "accepted"})
        # json.loads permits this result from a source JSON string with a
        # literal \\ud800 escape, although it cannot be encoded as UTF-8.
        emit({"host": cf.host, "message": "\ud800"})
        return [], "syslog", 2, 0

    monkeypatch.setattr(stage_mod, "_parse", parse_bad_text)
    result = stage_mod.stage_aux_file(_source(tmp_path), tmp_path / "stage",
                                      options=IngestOptions(staging_format=format))
    assert result.status == "partial"
    assert result.error_count == 1
    assert result.record_count == sum(chunk.record_count for chunk in result.chunks) == 1
