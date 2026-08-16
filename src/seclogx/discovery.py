"""Discover .evtx files across one or more (possibly unrelated) source paths.

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
from pathlib import Path


@dataclass(frozen=True)
class SourceSpec:
    path: Path
    host: str | None = None


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    host: str
    size_bytes: int


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


def discover_evtx_files(sources: list[SourceSpec]) -> list[DiscoveredFile]:
    seen: dict[Path, DiscoveredFile] = {}
    for spec in sources:
        root = spec.path.resolve()
        if not root.exists():
            raise FileNotFoundError(f"source path does not exist: {root}")

        host = spec.host or root.name or str(root)

        if root.is_file():
            candidates = [root] if root.suffix.lower() == ".evtx" else []
        else:
            candidates = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx"]

        for p in candidates:
            resolved = p.resolve()
            if resolved in seen:
                continue
            seen[resolved] = DiscoveredFile(path=resolved, host=host, size_bytes=resolved.stat().st_size)

    return list(seen.values())
