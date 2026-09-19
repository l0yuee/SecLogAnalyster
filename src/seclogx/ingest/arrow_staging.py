"""Bounded columnar staging with the same raw VARCHAR contract as NDJSON.

Canonical numeric/time normalization stays in DuckDB. IPC avoids serializing
whole rows to JSON and reparsing them, while bounded record batches prevent a
source file or conversion group from becoming one large in-memory table.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

import pyarrow as pa
import pyarrow.compute as pc

from .staging import StagedChunk


def raw_text(value) -> str | None:
    """Match scalar JSON spellings consumed by the fixed VARCHAR reader."""
    if value is None or isinstance(value, str):
        if isinstance(value, str) and not value.isascii():
            # Reject an invalid source string before accepting/counting its
            # row, rather than turning it into a later storage failure.
            value.encode("utf-8", errors="strict")
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (float, list, dict)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    else:
        text = str(value)
    if not text.isascii():
        text.encode("utf-8", errors="strict")
    return text


class ArrowStagingWriter:
    """Write ZSTD IPC shards, with independent bounds on buffers and rows."""

    max_record_bytes = 32 * 1024 * 1024
    max_batch_bytes = 16 * 1024 * 1024
    max_batch_rows = 16_384
    output_buffer_bytes = 1024 * 1024

    def __init__(self, path: Path, chunk_bytes: int, columns: Iterable[str]):
        if chunk_bytes <= 0:
            raise ValueError("staging chunk size must be positive")
        self.path = Path(path)
        self.chunk_bytes = chunk_bytes
        self.schema = pa.schema([(name, pa.string()) for name in columns])
        self._schema_row_overhead = 64 * len(self.schema)
        self._field_overhead = {name: 6 * len(name) + 8 for name in self.schema.names}
        self._rows = []
        self._buffer_bytes = 0
        self._batch_limit = min(chunk_bytes, self.max_batch_bytes)
        self.chunks: list[StagedChunk] = []
        self.record_count = 0
        self._path = self.path
        self._sink = self._writer = None
        self._bytes = self._records = 0
        self._failure: BaseException | None = None
        self._aborted = False
        self._abort_complete = False
        # A file worker owns this budget; do not start an extra global pool
        # for each worker merely to compress a small batch.
        self._options = pa.ipc.IpcWriteOptions(compression=pa.Codec("zstd", compression_level=1), use_threads=False)

    def write(self, row: dict) -> None:
        # JSON control-character escapes can take six bytes per codepoint.
        # Keep unknown fields in this bound too: the old writer's record cap
        # applies before the fixed-schema reader discards extra columns.
        values = {}
        size = self._schema_row_overhead
        field_overhead = self._field_overhead
        for key, value in row.items():
            value = raw_text(value)
            values[key] = value
            overhead = field_overhead.get(key)
            if overhead is None:
                overhead = 6 * len(key) + 8
            size += overhead + (6 * len(value) if value is not None else 4)
        if size > self.max_record_bytes:
            # Do not reject a long ASCII record solely due to the conservative
            # estimate. Preserve the established encoded-row limit.
            actual = len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1
            if actual > self.max_record_bytes:
                raise ValueError(f"encoded log record exceeds {self.max_record_bytes} bytes")
        if self._rows and (self._buffer_bytes + size > self._batch_limit or len(self._rows) >= self.max_batch_rows):
            self._flush_batch()
        self._rows.append(values)
        self._buffer_bytes += size
        self.record_count += 1
        if self._buffer_bytes >= self._batch_limit:
            self._flush_batch()

    def write_batch(self, batch: pa.RecordBatch, *, encoded_record_sizes: pa.Array) -> None:
        """Accept a bounded batch from a trusted, raw-VARCHAR producer.

        ``encoded_record_sizes`` is a non-null uint64 array containing the
        original row's compact JSON UTF-8 size plus its newline, or a safe
        upper bound. It must include fields omitted from the fixed schema.
        Producers must resolve bounds above ``max_record_bytes`` against the
        exact encoding, so conservative estimates do not reject valid rows.

        This internal interface cannot reconstruct original JSON types from
        VARCHAR columns. It checks the supplied limits, UTF-8, schema and raw
        payload lengths; the producer owns JSON escaping/type equivalence and
        accounting for discarded fields. A single valid long record may
        exceed the normal batch target. Larger multirow batches are rejected
        before acceptance, rather than retained as an unbounded buffer.
        """
        if self._failure is not None:
            self._reject_write(None)
        self._validate_batch(batch, encoded_record_sizes)
        if not batch.num_rows:
            return
        # Preserve the order when a caller mixes legacy rows and native
        # batches. Invalid input above does not flush or discard a prefix.
        self._flush_batch()
        try:
            for part in self._batch_slices(batch):
                self.record_count += part.num_rows
                self._write_arrow_batch(part)
        except Exception as exc:
            self._mark_failed(exc)
            raise OSError(f"Arrow staging write failed: {self._path}") from exc

    def _validate_batch(self, batch: pa.RecordBatch, encoded_record_sizes: pa.Array) -> None:
        if not isinstance(batch, pa.RecordBatch):
            raise TypeError("Arrow staging batch must be a RecordBatch")
        if not batch.schema.equals(self.schema, check_metadata=True):
            raise ValueError("Arrow staging batch must use the writer's raw VARCHAR schema")
        if (not isinstance(encoded_record_sizes, pa.Array)
                or encoded_record_sizes.type != pa.uint64()):
            raise TypeError("encoded_record_sizes must be a uint64 Arrow array")
        if len(encoded_record_sizes) != batch.num_rows or encoded_record_sizes.null_count:
            raise ValueError("encoded_record_sizes must contain one non-null size per row")
        if batch.num_rows > self.max_batch_rows:
            raise ValueError(f"Arrow staging batch exceeds {self.max_batch_rows} rows")
        if batch.num_rows > 1 and batch.nbytes > self.max_batch_bytes:
            raise ValueError(f"Arrow staging batch exceeds {self.max_batch_bytes} bytes")
        if batch.num_rows == 1 and batch.nbytes > self.max_record_bytes + self._schema_row_overhead:
            raise ValueError(f"encoded log record exceeds {self.max_record_bytes} bytes")
        batch.validate(full=True)
        encoded_record_sizes.validate(full=True)
        if not batch.num_rows:
            return
        bounds = pc.min_max(encoded_record_sizes).as_py()
        if bounds["min"] <= 0:
            raise ValueError("encoded_record_sizes must be positive")
        if bounds["max"] > self.max_record_bytes:
            raise ValueError(f"encoded log record exceeds {self.max_record_bytes} bytes")
        # Independently reject an understated bound even for the one-row
        # exception. These are native array operations, not Python row loops.
        payload_sizes = pa.repeat(0, batch.num_rows)
        for column in batch.columns:
            payload_sizes = pc.add(payload_sizes, pc.fill_null(pc.binary_length(column), 0))
        if pc.any(pc.greater(payload_sizes, encoded_record_sizes)).as_py():
            raise ValueError("encoded_record_sizes is smaller than the raw record payload")

    def _batch_slices(self, batch: pa.RecordBatch) -> Iterator[pa.RecordBatch]:
        """Use views to honor small shard targets without splitting a row."""
        offset = 0
        while offset < batch.num_rows:
            length = min(batch.num_rows - offset, self.max_batch_rows)
            part = batch.slice(offset, length)
            if length > 1 and part.nbytes > self._batch_limit:
                low, high = 1, length
                while low < high:
                    middle = (low + high + 1) // 2
                    if batch.slice(offset, middle).nbytes <= self._batch_limit:
                        low = middle
                    else:
                        high = middle - 1
                part = batch.slice(offset, low)
            yield part
            offset += part.num_rows

    def _flush_batch(self) -> None:
        if self._failure is not None:
            self._reject_write(None)
        try:
            self._write_batch()
        except Exception as exc:
            self._mark_failed(exc)
            raise OSError(f"Arrow staging write failed: {self._path}") from exc

    def _mark_failed(self, exc: BaseException) -> None:
        if self._failure is None:
            self._failure = exc
            # Reject subsequent writes without adding a check to every record
            # in the normal path. A failed writer must never buffer more rows.
            self.write = self._reject_write
        self._rows.clear()
        self._buffer_bytes = 0

    def _reject_write(self, row) -> None:
        raise OSError(f"Arrow staging writer has failed: {self._path}") from self._failure

    def _write_batch(self) -> None:
        if not self._rows:
            return
        batch = pa.RecordBatch.from_pylist(self._rows, schema=self.schema)
        self._write_arrow_batch(batch)
        self._rows.clear()
        self._buffer_bytes = 0

    def _write_arrow_batch(self, batch: pa.RecordBatch) -> None:
        if self._writer is not None and self._bytes + batch.nbytes > self.chunk_bytes:
            self._close_shard()
        if self._writer is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._path = self.path if not self.chunks else self.path.with_name(
                f"{self.path.stem}.{len(self.chunks):06d}.arrow"
            )
            # IPC emits many small metadata/column writes. Coalesce them with
            # a fixed per-worker buffer; compression belongs to IPC itself.
            self._sink = pa.output_stream(
                str(self._path), compression=None, buffer_size=self.output_buffer_bytes
            )
            try:
                self._writer = pa.ipc.new_file(self._sink, self.schema, options=self._options)
            except BaseException:
                self._sink.close()
                self._sink = None
                self._path.unlink(missing_ok=True)
                raise
            self._bytes = self._records = 0
        self._writer.write_batch(batch)
        self._bytes += batch.nbytes
        self._records += batch.num_rows

    def _close_shard(self) -> None:
        if self._writer is None:
            return
        try:
            self._writer.close()
        finally:
            self._writer = None
            self._sink.close()
            self._sink = None
        self.chunks.append(StagedChunk(str(self._path), self._bytes, self._records))

    def close(self) -> None:
        if self._aborted:
            return
        if self._failure is not None:
            # A failed rotation can leave a live sink after _writer was reset.
            # Reflushing would reopen its path and overwrite that sink handle.
            self._discard_current()
            self._reject_write(None)
        try:
            self._flush_batch()
            self._close_shard()
        except BaseException as exc:
            self._mark_failed(exc)
            self._discard_current()
            if isinstance(exc, Exception) and not isinstance(exc, OSError):
                raise OSError(f"Arrow staging close failed: {self._path}") from exc
            raise

    def abort(self) -> None:
        """Discard this source's output before an explicit whole-file retry.

        Closing an aborted writer is harmless (also during exception unwind),
        but it cannot accept more input. Unlike fatal-error best-effort cleanup,
        deletion failures propagate so callers cannot retry with stale shards.
        """
        if self._abort_complete:
            return
        self._aborted = True
        self._mark_failed(OSError("Arrow staging writer was aborted"))
        self._discard_current()
        self._path.unlink(missing_ok=True)
        for chunk in self.chunks:
            Path(chunk.path).unlink(missing_ok=True)
        self.chunks.clear()
        self.record_count = 0
        self._bytes = self._records = 0
        self._abort_complete = True

    def _discard_current(self) -> None:
        # Never present an incompletely flushed IPC file as a good shard.
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        if self._sink is not None:
            try:
                self._sink.close()
            except Exception:
                pass
            self._sink = None
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass  # Keep the first persistence failure as the fatal cause.

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def iter_arrow_batches(paths: Iterable[str], schema: pa.Schema) -> Iterator[pa.RecordBatch]:
    """Open only the current shard and decompress only the current batch."""
    for path in paths:
        with pa.memory_map(str(path), "r") as source:
            reader = pa.ipc.open_file(source)
            if reader.schema != schema:
                raise ValueError(f"inconsistent Arrow staging schema: {path}")
            for index in range(reader.num_record_batches):
                yield reader.get_batch(index)


@contextmanager
def arrow_reader(paths: list[str], columns: Iterable[str]):
    schema = pa.schema([(name, pa.string()) for name in columns])
    batches = iter_arrow_batches(paths, schema)
    reader = pa.RecordBatchReader.from_batches(schema, batches)
    try:
        yield reader
    finally:
        try:
            reader.close()
        finally:
            batches.close()
