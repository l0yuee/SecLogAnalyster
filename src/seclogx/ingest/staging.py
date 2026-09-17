"""Bounded NDJSON shards shared by the EVTX and auxiliary pipelines."""

from __future__ import annotations

import gzip
import io
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class StagedChunk:
    path: str
    size_bytes: int  # Uncompressed bytes: compressed size is not a memory budget.
    record_count: int


class StagingWriter:
    """Keep one encoded record in memory; rotate only between records.

    The first shard retains the old filename. A single record larger than
    the shard target occupies its own shard; records above 32 MiB are
    explicitly rejected rather than silently truncated.
    """

    max_record_bytes = 32 * 1024 * 1024

    def __init__(self, path: Path, chunk_bytes: int):
        if chunk_bytes <= 0:
            raise ValueError("staging chunk size must be positive")
        self.path = Path(path)
        self.chunk_bytes = chunk_bytes
        self.chunks: list[StagedChunk] = []
        self.record_count = 0
        self._stream = None
        self._path = self.path
        self._bytes = self._records = 0
        self._encode = json.JSONEncoder(default=str, ensure_ascii=False, separators=(",", ":")).encode

    def write(self, row: dict) -> None:
        data = (self._encode(row) + "\n").encode("utf-8")
        if len(data) > self.max_record_bytes:
            raise ValueError(f"encoded log record exceeds {self.max_record_bytes} bytes")
        if self._stream is not None and self._bytes + len(data) > self.chunk_bytes:
            self.close()
        if self._stream is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._path = self.path if not self.chunks else self.path.with_name(
                f"{self.path.name.removesuffix('.ndjson.gz')}.{len(self.chunks):06d}.ndjson.gz"
            )
            # Feed zlib bounded blocks instead of calling its compressor once
            # per JSON record. This retains streaming memory use while avoiding
            # millions of tiny compression calls on ordinary access logs.
            self._stream = io.BufferedWriter(
                gzip.open(self._path, "wb", compresslevel=1), buffer_size=256 * 1024
            )
            self._bytes = self._records = 0
        self._stream.write(data)
        self._bytes += len(data)
        self._records += 1
        self.record_count += 1

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
            self.chunks.append(StagedChunk(str(self._path), self._bytes, self._records))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def staged_chunks(staged) -> list[StagedChunk]:
    if staged.chunks:
        return staged.chunks
    if staged.ndjson_path:
        # Compatibility with manifests created by earlier callers/tests.
        path = Path(staged.ndjson_path)
        return [StagedChunk(str(path), path.stat().st_size, staged.record_count)]
    return []


def staged_batches(files: Iterable, max_bytes: int) -> Iterator[list]:
    """Yield manifest slices bounded by uncompressed shard bytes.

    A shard (or one unusually large record) is indivisible. The writer's
    shard target bounds that overshoot independently of source-file size.
    """
    batch = []
    size = 0
    for staged in files:
        for chunk in staged_chunks(staged):
            if batch and size + chunk.size_bytes > max_bytes:
                yield batch
                batch, size = [], 0
            batch.append(replace(staged, ndjson_path=chunk.path, record_count=chunk.record_count, chunks=[]))
            size += chunk.size_bytes
    if batch:
        yield batch


def remove_staged(staged) -> None:
    for chunk in staged_chunks(staged):
        Path(chunk.path).unlink(missing_ok=True)
