"""Discover .evtx files across one or more (possibly unrelated) source paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..common import SourceSpec


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    host: str
    size_bytes: int


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
