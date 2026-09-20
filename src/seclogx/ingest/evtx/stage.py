"""Recover EVTX records into bounded columnar or gzip NDJSON shards."""

from __future__ import annotations

import hashlib
import sqlite3
import struct
import uuid
from pathlib import Path

from evtx import PyEvtxParser

from ..common import StageStatus, now_iso
from ..resources import IngestOptions
from ..staging import StagingWriter
from ..arrow_staging import ArrowStagingWriter
from ..activity import workspace_worker
from ..activity import workspace_worker
from .discovery import DiscoveredFile
from .encoding import normalize_ansi_codec
from .manifest import StagedFile
from ...textdecode import SourceChangedError, _stat_signature

_ARROW_THRESHOLD_BYTES = 16 * 1024 * 1024
_RAW_COLUMNS = ("event_record_id", "timestamp", "data")


def _prepare_evtx(path: Path) -> tuple[str, int | None, bool]:
    """Hash every source byte and audit bounded chunk headers in the same pass.

    Counters at offsets 8/16 are physical record ordinals, not EventRecordID.
    Damaged/empty headers do not contribute a guessed count. A valid header
    establishes a lower bound when other chunks cannot be audited; even all
    valid headers are only a consistency check, not proof of authenticity.
    """
    digest = hashlib.sha256()
    declared = 0
    audited = False
    all_valid = True
    with path.open("rb") as source:
        digest.update(source.read(4096))
        while chunk := source.read(65536):
            digest.update(chunk)
            if chunk[:8] == b"\0" * 8 and chunk.count(0) == len(chunk):
                continue  # unused allocated chunk, not a declared record
            if len(chunk) != 65536 or chunk[:8] != b"ElfChnk\0":
                all_valid = False
                continue
            first, last = struct.unpack_from("<QQ", chunk, 8)
            header_size, last_offset, free_offset = struct.unpack_from("<III", chunk, 40)
            if header_size != 128 or not (512 <= last_offset < free_offset <= 65536) or last < first:
                all_valid = False
                continue
            count = last - first + 1
            if count > (free_offset - 512) // 24:
                all_valid = False
                continue
            declared += count
            audited = True
    return digest.hexdigest(), declared if audited else None, all_valid


def _recover_records(iterator, size_bytes: int, on_error):
    """The native iterator advances past corrupt chunks before raising.

    Catch only errors from next(), never writer/storage failures. A physical
    EVTX record occupies at least 24 bytes, giving a finite guard against a
    broken iterator that raises forever without advancing.
    """
    attempts = 0
    maximum = max(1024, size_bytes // 24 + size_bytes // 65536 + 2)
    while attempts < maximum:
        attempts += 1
        try:
            record = next(iterator)
        except StopIteration:
            return
        except RuntimeError as exc:
            on_error(str(exc))
            continue
        yield record
    raise RuntimeError("EVTX recovery iteration exceeded the physical input bound")


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


@workspace_worker
@workspace_worker
def stage_file(
    discovered: DiscoveredFile, staging_dir: Path, keep_raw: bool = False,
    options: IngestOptions | None = None,
) -> StagedFile:
    options = options or IngestOptions()
    source_path, host = discovered.path, discovered.host
    ansi_codec = normalize_ansi_codec(discovered.ansi_codec)
    codec_source = "source" if discovered.ansi_codec is not None else "default"
    host_dir = staging_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)
    identity = str(source_path) + "\0" + ansi_codec
    use_arrow = options.staging_format == "arrow" or (
        options.staging_format == "auto" and discovered.size_bytes >= _ARROW_THRESHOLD_BYTES
    )
    suffix = ".arrow" if use_arrow else ".ndjson.gz"
    ndjson_path = host_dir / f"{source_path.stem}.{_short_hash(identity)}{suffix}"
    try:
        source_signature = _stat_signature(source_path.stat())
        file_sha256, header_record_count, all_headers_audited = _prepare_evtx(source_path)
        if _stat_signature(source_path.stat()) != source_signature:
            raise SourceChangedError(f"EVTX source changed while hashing: {source_path}")
    except SourceChangedError:
        raise
    except OSError as exc:
        return StagedFile(
            source_path=str(source_path), source_file=source_path.name, host=host,
            file_sha256="", size_bytes=discovered.size_bytes, status=StageStatus.FAILED,
            record_count=0, error_count=0, error_message=f"could not read file: {exc}",
            ndjson_path=None, staged_at=now_iso(),
            ansi_codec=ansi_codec, ansi_codec_source=codec_source,
        )

    columns = _RAW_COLUMNS + (("raw_xml",) if keep_raw else ())
    writer = (ArrowStagingWriter(ndjson_path, options.staging_chunk_bytes, columns) if use_arrow
              else StagingWriter(ndjson_path, options.staging_chunk_bytes))
    error_count = 0
    error_message = None
    raw_index = None
    raw_index_path = None

    def on_error(message: str) -> None:
        nonlocal error_count, error_message
        error_count += 1
        # Preserve a useful diagnosis without retaining every corrupt record.
        if error_message is None:
            error_message = message[:2048]

    def parser():
        # File workers own parallelism. A native all-core pool per source
        # wastes threads and defeats the caller's aggregate process budget.
        return PyEvtxParser(str(source_path), number_of_threads=1, ansi_codec=ansi_codec)

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
                for rec in _recover_records(iter(parser().records()), discovered.size_bytes,
                                            lambda message: on_error("raw XML: " + message)):
                    rid = rec.get("event_record_id")
                    if rid is not None and "data" in rec:
                        raw_index.execute("INSERT OR REPLACE INTO raw_xml VALUES (?, ?)", (rid, rec["data"]))
            except (OSError, sqlite3.Error, MemoryError):
                # Index write failures (for example a full disk) must not
                # silently turn keep_raw=True into missing XML evidence.
                raise
            except Exception as exc:
                # XML capture is best effort; JSON recovery below remains
                # authoritative on malformed chunks.
                on_error("raw XML: " + str(exc))
            raw_index.commit()

        with writer:
            for rec in _recover_records(iter(parser().records_json()), discovered.size_bytes, on_error):
                if not isinstance(rec, dict) or "data" not in rec or "event_record_id" not in rec:
                    on_error("invalid EVTX parser record envelope")
                    continue
                if raw_index is not None:
                    rec = dict(rec)
                    raw = raw_index.execute(
                        "SELECT xml FROM raw_xml WHERE record_id = ?", (rec["event_record_id"],)
                    ).fetchone()
                    rec["raw_xml"] = raw[0] if raw else None
                    if raw is None:
                        on_error(f"raw XML unavailable for record {rec['event_record_id']}")
                writer.write(rec)
    except (OSError, sqlite3.Error, MemoryError):
        raise
    except Exception as exc:
        on_error(str(exc))
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

    if _stat_signature(source_path.stat()) != source_signature:
        raise SourceChangedError(f"EVTX source changed while parsing: {source_path}")

    record_count = writer.record_count
    if header_record_count is not None and (
        record_count < header_record_count or (all_headers_audited and record_count != header_record_count)
    ):
        on_error(f"EVTX header count mismatch: {header_record_count} declared records, {record_count} recovered")
    status = StageStatus.FAILED if not record_count else (
        StageStatus.PARTIAL if error_message or error_count else StageStatus.OK
    )
    return StagedFile(
        source_path=str(source_path), source_file=source_path.name, host=host,
        file_sha256=file_sha256, size_bytes=discovered.size_bytes, status=status,
        record_count=record_count, error_count=error_count, error_message=error_message,
        ndjson_path=writer.chunks[0].path if writer.chunks else None, staged_at=now_iso(),
        chunks=writer.chunks,
        ansi_codec=ansi_codec, ansi_codec_source=codec_source,
        staging_format="arrow" if use_arrow else "ndjson",
        header_record_count=header_record_count,
    )
