"""Primitives shared by both ingest pipelines (`ingest/evtx/`, `ingest/logsources/`):
source-path parsing/hashing, and the staging status vocabulary + timestamp
helper each pipeline's manifest uses to report what happened to every file.

Forensic acquisitions rarely live under one tidy directory -- a case might
combine a KAPE output folder for host A, a mounted image path for host B,
and a handful of files copied out manually. `--source` is repeatable and
each value may carry an explicit host label (`PATH:HOST`); when omitted,
the source root's directory (or file) name is used as the host label, which
matches common triage-tool layouts (e.g. `<HOST>/C/Windows/System32/winevt/Logs/...`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class SourceSpec:
    path: Path
    host: str | None = None


def parse_source_arg(raw: str) -> SourceSpec:
    """Parse a `--source` CLI value of the form `PATH` or `PATH:HOST`."""
    if ":" in raw:
        path_part, _, host_part = raw.rpartition(":")
        # Guard against POSIX absolute paths or Windows drive letters that
        # merely contain a colon with no real host label after them
        # (e.g. "/mnt/E:evidence" is unlikely, but "C:\evidence" is common
        # when a Windows path is pasted in verbatim).
        if path_part and host_part and "/" not in host_part and "\\" not in host_part:
            return SourceSpec(path=Path(path_part), host=host_part)
    return SourceSpec(path=Path(raw), host=None)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


class StageStatus:
    OK = "ok"
    PARTIAL = "partial"  # some records/rows recovered, then a parse error stopped the rest
    FAILED = "failed"  # zero records/rows recovered (e.g. corrupt/unreadable header)
    UNKNOWN = "unknown"  # content didn't match any supported format (logsources pipeline only)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
