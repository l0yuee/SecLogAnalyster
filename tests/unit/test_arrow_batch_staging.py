"""Local regression coverage for raw-VARCHAR batch staging and legacy writes."""
from __future__ import annotations

import json
import struct
from datetime import datetime
from pathlib import Path

import pyarrow as pa
import pytest

from seclogx.ingest.arrow_staging import ArrowStagingWriter, arrow_reader, raw_text


def _size(row):
    return len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1


def _batch(writer, rows):
    normalized = [{key: raw_text(value) for key, value in row.items()} for row in rows]
    return (pa.RecordBatch.from_pylist(normalized, schema=writer.schema),
            pa.array([_size(row) for row in rows], type=pa.uint64()))


def _read(writer):
    with arrow_reader([chunk.path for chunk in writer.chunks], writer.schema.names) as reader:
        return reader.read_all().to_pylist()


def test_batch_and_legacy_writes_keep_raw_values_order_and_counts(tmp_path):
    rows = [
        {"id": 0, "value": None},
        {"id": 1, "value": ""},
        {"id": 2, "value": "中文\n\x00\\\"", "extra": {"nested": [None, False, 1.5]}},
        {"id": 3, "value": True, "extra": "000123"},
        {"id": 4, "value": 2**64, "extra": float("nan")},
        {"id": 5, "value": -0.0, "extra": datetime(2026, 9, 18, 12)},
        {"id": 6, "value": "2026-09-18T08:00:00.123456+08:00", "unknown": "discarded"},
    ]
    expected = ArrowStagingWriter(tmp_path / "legacy.arrow", 120, ["id", "value", "extra"])
    with expected:
        for row in rows:
            expected.write(row)
    actual = ArrowStagingWriter(tmp_path / "batch.arrow", 120, expected.schema.names)
    with actual:
        actual.write(rows[0])
        batch, sizes = _batch(actual, rows[1:-1])
        actual.write_batch(batch, encoded_record_sizes=sizes)
        actual.write(rows[-1])
    assert _read(actual) == _read(expected)
    assert actual.record_count == sum(chunk.record_count for chunk in actual.chunks) == len(rows)
    assert len(actual.chunks) > 1
    assert actual._rows == []
    assert actual._buffer_bytes == 0


def test_legacy_cap_still_includes_unknown_fields_and_exact_json_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 200)
    writer = ArrowStagingWriter(tmp_path / "legacy.arrow", 1000, ["value"])
    with writer:
        # Conservative six-byte estimates must not reject this valid row.
        writer.write({"value": "a" * 100, "unknown": None})
        with pytest.raises(ValueError, match="encoded log record"):
            writer.write({"value": "small", "unknown": "\x00" * 100})
        with pytest.raises(UnicodeEncodeError):
            writer.write({"value": "valid", "unknown": "\ud800"})
    assert _read(writer) == [{"value": "a" * 100}]
    assert writer.record_count == 1


@pytest.mark.parametrize("invalid", ["wrong-type", "wrong-length", "null", "zero", "oversize", "understated"])
def test_batch_size_contract_rejects_before_acceptance(tmp_path, monkeypatch, invalid):
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 200)
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1000, ["value"])
    batch, sizes = _batch(writer, [{"value": "batch"}])
    sizes = {
        "wrong-type": pa.array([10], type=pa.int64()),
        "wrong-length": pa.array([], type=pa.uint64()),
        "null": pa.array([None], type=pa.uint64()),
        "zero": pa.array([0], type=pa.uint64()),
        "oversize": pa.array([201], type=pa.uint64()),
        "understated": pa.array([1], type=pa.uint64()),
    }[invalid]
    with writer:
        writer.write({"value": "prefix"})
        with pytest.raises((TypeError, ValueError)):
            writer.write_batch(batch, encoded_record_sizes=sizes)
        assert writer.record_count == 1
        assert writer._failure is None
    assert _read(writer) == [{"value": "prefix"}]


def test_batch_cap_accounts_for_discarded_original_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 200)
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1000, ["value"])
    batch, sizes = _batch(writer, [{"value": "valid", "unknown": "\x00" * 100}])
    with writer, pytest.raises(ValueError, match="encoded log record"):
        writer.write_batch(batch, encoded_record_sizes=sizes)
    assert writer.record_count == 0
    assert writer.chunks == []


def test_batch_rejects_schema_mismatch_and_invalid_utf8(tmp_path):
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1000, ["value"])
    bad_schema = pa.record_batch([pa.array([1])], names=["value"])
    bad_utf8 = pa.Array.from_buffers(
        pa.string(), 1,
        [None, pa.py_buffer(struct.pack("<ii", 0, 1)), pa.py_buffer(b"\xff")],
    )
    with writer:
        writer.write({"value": "prefix"})
        with pytest.raises(ValueError, match="raw VARCHAR schema"):
            writer.write_batch(bad_schema, encoded_record_sizes=pa.array([20], type=pa.uint64()))
        with pytest.raises(pa.ArrowInvalid):
            writer.write_batch(pa.record_batch([bad_utf8], schema=writer.schema),
                               encoded_record_sizes=pa.array([20], type=pa.uint64()))
    assert _read(writer) == [{"value": "prefix"}]


def test_batch_rejects_unbounded_multirow_input_but_accepts_long_single_row(tmp_path, monkeypatch):
    monkeypatch.setattr(ArrowStagingWriter, "max_batch_rows", 2)
    monkeypatch.setattr(ArrowStagingWriter, "max_batch_bytes", 64)
    monkeypatch.setattr(ArrowStagingWriter, "max_record_bytes", 200)
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 16, ["value"])
    with writer:
        for rows in ([{"value": "a"}] * 3, [{"value": "a" * 40}] * 2):
            batch, sizes = _batch(writer, rows)
            with pytest.raises(ValueError, match="Arrow staging batch exceeds"):
                writer.write_batch(batch, encoded_record_sizes=sizes)
        for row in ({"value": "start"}, {"value": "a" * 100}, {"value": "end"}):
            batch, sizes = _batch(writer, [row])
            writer.write_batch(batch, encoded_record_sizes=sizes)
    assert [row["value"] for row in _read(writer)] == ["start", "a" * 100, "end"]
    assert [chunk.record_count for chunk in writer.chunks] == [1, 1, 1]


def test_empty_batch_is_a_noop(tmp_path):
    writer = ArrowStagingWriter(tmp_path / "empty.arrow", 1000, ["value"])
    batch, sizes = _batch(writer, [])
    with writer:
        writer.write_batch(batch, encoded_record_sizes=sizes)
    assert writer.record_count == 0
    assert writer.chunks == []
    assert not writer.path.exists()


def test_native_write_failure_is_sticky_and_abort_removes_all_shards(tmp_path, monkeypatch):
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1, ["value"])
    batch, sizes = _batch(writer, [{"value": "native"}])
    writer.write_batch(batch, encoded_record_sizes=sizes)
    original = writer._write_arrow_batch
    cause = RuntimeError("injected native persistence failure")

    def fail_after_write(part):
        original(part)
        raise cause

    monkeypatch.setattr(writer, "_write_arrow_batch", fail_after_write)
    with pytest.raises(OSError) as failure:
        writer.write_batch(batch, encoded_record_sizes=sizes)
    assert failure.value.__cause__ is cause
    count = writer.record_count
    for operation in (lambda: writer.write({"value": "reject"}),
                      lambda: writer.write_batch(batch, encoded_record_sizes=sizes)):
        with pytest.raises(OSError, match="writer has failed") as rejected:
            operation()
        assert rejected.value.__cause__ is cause
    assert writer.record_count == count
    assert writer._rows == []
    assert writer._buffer_bytes == 0
    writer.abort()
    writer.close()
    assert writer.chunks == []
    assert writer.record_count == 0
    assert not list(tmp_path.glob("*.arrow"))


def test_abort_preserves_unwinding_exception_and_cannot_be_reused(tmp_path):
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1, ["value"])
    batch, sizes = _batch(writer, [{"value": "native"}, {"value": "second"}])
    with pytest.raises(ValueError, match="unsupported input"):
        with writer:
            writer.write_batch(batch, encoded_record_sizes=sizes)
            assert writer.chunks
            writer.abort()
            raise ValueError("unsupported input")
    writer.abort()
    writer.close()
    assert not list(tmp_path.glob("*.arrow"))
    assert writer.chunks == []
    assert writer.record_count == 0
    with pytest.raises(OSError, match="writer has failed"):
        writer.write_batch(batch, encoded_record_sizes=sizes)


def test_abort_propagates_deletion_failure_before_retry(tmp_path, monkeypatch):
    writer = ArrowStagingWriter(tmp_path / "rows.arrow", 1, ["value"])
    batch, sizes = _batch(writer, [{"value": "native"}])
    writer.write_batch(batch, encoded_record_sizes=sizes)
    original = Path.unlink

    def denied(path, *args, **kwargs):
        if path == writer.path:
            raise PermissionError("injected delete failure")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", denied)
        with pytest.raises(PermissionError, match="injected delete failure"):
            writer.abort()
    writer.abort()
    writer.close()
    assert not list(tmp_path.glob("*.arrow"))


def test_repeated_abort_cannot_delete_a_replacement_writers_output(tmp_path):
    path = tmp_path / "rows.arrow"
    original = ArrowStagingWriter(path, 1000, ["value"])
    original.write({"value": "discard"})
    original.abort()
    replacement = ArrowStagingWriter(path, 1000, ["value"])
    with replacement:
        replacement.write({"value": "replacement"})
    original.abort()
    original.close()
    assert _read(replacement) == [{"value": "replacement"}]
