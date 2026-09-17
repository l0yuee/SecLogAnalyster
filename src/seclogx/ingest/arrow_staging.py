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
        self._rows = []
        self._buffer_bytes = 0
        self._batch_limit = min(chunk_bytes, self.max_batch_bytes)
        self.chunks: list[StagedChunk] = []
        self.record_count = 0
        self._path = self.path
        self._sink = self._writer = None
        self._bytes = self._records = 0
        self._failure: BaseException | None = None
        # A file worker owns this budget; do not start an extra global pool
        # for each worker merely to compress a small batch.
        self._options = pa.ipc.IpcWriteOptions(compression=pa.Codec("zstd", compression_level=1), use_threads=False)

    def write(self, row: dict) -> None:
        values = {key: raw_text(value) for key, value in row.items()}
        # JSON control-character escapes can take six bytes per codepoint.
        # Keep unknown fields in this bound too: the old writer's record cap
        # applies before the fixed-schema reader discards extra columns.
        size = 64 * len(self.schema) + sum(
            6 * (len(key) + len(value)) + 8 if value is not None else 6 * len(key) + 12
            for key, value in values.items()
        )
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
        self._rows.clear()
        self._buffer_bytes = 0

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
