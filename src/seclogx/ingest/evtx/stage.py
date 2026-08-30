"""Per-file staging worker: streams one .evtx file to NDJSON.

Runs in a worker process (see orchestrator.py) since files are independent
and parsing is CPU/IO-bound -- this is where parallelism buys speed.

Empirically (tested against real corrupt sample files), `PyEvtxParser`
raises mid-generator on a bad chunk rather than yielding a per-record error
object, which means a corrupted chunk aborts the rest of the file's
iteration. We catch that at the file level and record a `partial` status
with however many good records were recovered before the failure --
never silently treating a partial read as a clean success.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evtx import PyEvtxParser

from ..common import StageStatus, now_iso, sha256_file
from .discovery import DiscoveredFile
from .manifest import StagedFile


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def stage_file(discovered: DiscoveredFile, staging_dir: Path, keep_raw: bool = False) -> StagedFile:
    source_path = discovered.path
    host = discovered.host
    host_dir = staging_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)

    # Hash suffix avoids collisions when files with the same basename are
    # discovered under the same host from different acquisition paths.
    ndjson_path = host_dir / f"{source_path.stem}.{_short_hash(str(source_path))}.ndjson"

    try:
        file_sha256 = sha256_file(source_path)
    except OSError as e:
        return StagedFile(
            source_path=str(source_path),
            source_file=source_path.name,
            host=host,
            file_sha256="",
            size_bytes=discovered.size_bytes,
            status=StageStatus.FAILED,
            record_count=0,
            error_count=0,
            error_message=f"could not read file: {e}",
            ndjson_path=None,
            staged_at=now_iso(),
        )

    # Best-effort raw XML capture for --keep-raw, keyed by record id so it
    # can be merged with the JSON pass even if one generator diverges from
    # the other on a corrupt chunk. Trades peak memory for correctness;
    # acceptable since --keep-raw is an explicit opt-in (see
    # docs/known_limitations.md).
    raw_xml_by_id: dict[int, str] = {}
    if keep_raw:
        try:
            for rec in PyEvtxParser(str(source_path)).records():
                rid = rec.get("event_record_id")
                if rid is not None and "data" in rec:
                    raw_xml_by_id[rid] = rec["data"]
        except Exception:
            pass  # raw XML capture is best-effort; the JSON pass below is authoritative

    try:
        parser = PyEvtxParser(str(source_path))
    except Exception as e:
        return StagedFile(
            source_path=str(source_path),
            source_file=source_path.name,
            host=host,
            file_sha256=file_sha256,
            size_bytes=discovered.size_bytes,
            status=StageStatus.FAILED,
            record_count=0,
            error_count=0,
            error_message=f"failed to open file: {e}",
            ndjson_path=None,
            staged_at=now_iso(),
        )

    record_count = 0
    error_count = 0
    error_message: str | None = None

    try:
        with ndjson_path.open("w") as out:
            for rec in parser.records_json():
                if not isinstance(rec, dict) or "data" not in rec or "event_record_id" not in rec:
                    error_count += 1
                    continue
                if keep_raw:
                    rec = dict(rec)
                    rec["raw_xml"] = raw_xml_by_id.get(rec["event_record_id"])
                out.write(json.dumps(rec) + "\n")
                record_count += 1
    except Exception as e:
        error_message = str(e)

    if record_count == 0:
        status = StageStatus.FAILED
        ndjson_path.unlink(missing_ok=True)
        ndjson_out = None
    elif error_message is not None:
        status = StageStatus.PARTIAL
        ndjson_out = str(ndjson_path)
    else:
        status = StageStatus.OK
        ndjson_out = str(ndjson_path)

    return StagedFile(
        source_path=str(source_path),
        source_file=source_path.name,
        host=host,
        file_sha256=file_sha256,
        size_bytes=discovered.size_bytes,
        status=status,
        record_count=record_count,
        error_count=error_count,
        error_message=error_message,
        ndjson_path=ndjson_out,
        staged_at=now_iso(),
    )
