"""Stream EVTX records to bounded gzip NDJSON shards."""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from pathlib import Path

from evtx import PyEvtxParser

from ..common import StageStatus, now_iso, sha256_file
from ..resources import IngestOptions
from ..staging import StagingWriter
from .discovery import DiscoveredFile
from .manifest import StagedFile


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def stage_file(
    discovered: DiscoveredFile, staging_dir: Path, keep_raw: bool = False,
    options: IngestOptions | None = None,
) -> StagedFile:
    options = options or IngestOptions()
    source_path, host = discovered.path, discovered.host
    host_dir = staging_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = host_dir / f"{source_path.stem}.{_short_hash(str(source_path))}.ndjson.gz"
    try:
        file_sha256 = sha256_file(source_path)
    except OSError as exc:
        return StagedFile(
            source_path=str(source_path), source_file=source_path.name, host=host,
            file_sha256="", size_bytes=discovered.size_bytes, status=StageStatus.FAILED,
            record_count=0, error_count=0, error_message=f"could not read file: {exc}",
            ndjson_path=None, staged_at=now_iso(),
        )

    writer = StagingWriter(ndjson_path, options.staging_chunk_bytes)
    error_count = 0
    error_message = None
    raw_index = None
    raw_index_path = None
    try:
        if keep_raw:
            # The optional second parse still costs CPU/I/O, but raw XML
            # must not accumulate as a whole-file Python dictionary.
            raw_index_path = host_dir / f".raw-{uuid.uuid4().hex}.sqlite"
            raw_index = sqlite3.connect(raw_index_path)
            raw_index.execute("PRAGMA cache_size=-2048")
            raw_index.execute("PRAGMA temp_store=FILE")
            raw_index.execute("CREATE TABLE raw_xml (record_id INTEGER PRIMARY KEY, xml TEXT)")
            try:
                for rec in PyEvtxParser(str(source_path)).records():
                    rid = rec.get("event_record_id")
                    if rid is not None and "data" in rec:
                        raw_index.execute("INSERT OR REPLACE INTO raw_xml VALUES (?, ?)", (rid, rec["data"]))
            except sqlite3.Error:
                # Index write failures (for example a full disk) must not
                # silently turn keep_raw=True into missing XML evidence.
                raise
            except Exception:
                # XML capture is best effort; JSON recovery below remains
                # authoritative on malformed chunks.
                pass
            raw_index.commit()

        with writer:
            for rec in PyEvtxParser(str(source_path)).records_json():
                if not isinstance(rec, dict) or "data" not in rec or "event_record_id" not in rec:
                    error_count += 1
                    continue
                if raw_index is not None:
                    rec = dict(rec)
                    raw = raw_index.execute(
                        "SELECT xml FROM raw_xml WHERE record_id = ?", (rec["event_record_id"],)
                    ).fetchone()
                    rec["raw_xml"] = raw[0] if raw else None
                writer.write(rec)
    except (OSError, sqlite3.Error):
        raise
    except Exception as exc:
        error_message = str(exc)
        error_count += 1
    finally:
        try:
            writer.close()
        finally:
            try:
                if raw_index is not None:
                    raw_index.close()
            finally:
                if raw_index_path is not None:
                    raw_index_path.unlink(missing_ok=True)

    record_count = writer.record_count
    status = StageStatus.FAILED if not record_count else (
        StageStatus.PARTIAL if error_message or error_count else StageStatus.OK
    )
    return StagedFile(
        source_path=str(source_path), source_file=source_path.name, host=host,
        file_sha256=file_sha256, size_bytes=discovered.size_bytes, status=status,
        record_count=record_count, error_count=error_count, error_message=error_message,
        ndjson_path=writer.chunks[0].path if writer.chunks else None, staged_at=now_iso(),
        chunks=writer.chunks,
    )
