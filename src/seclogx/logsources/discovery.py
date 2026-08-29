"""Discover and classify non-.evtx files under the same `--source` inputs
used for EVTX discovery. Runs as a second pass over the same source trees
(`.evtx` files are skipped -- those stay owned by the existing EVTX
pipeline), so one `--source` covers every supported artifact type.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..discovery import SourceSpec, sha256_file
from .sniff import classify_file

# Extensions cheap to skip outright: known-binary or clearly irrelevant.
_SKIP_SUFFIXES = {
    ".evtx", ".exe", ".dll", ".sys", ".zip", ".gz", ".7z", ".rar", ".pf", ".dmp",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".db", ".sqlite",
}

# Files above this size aren't peeked -- avoids stat/open overhead across huge
# binary evidence (memory dumps, disk images) accidentally left under a source root.
_MAX_CANDIDATE_SIZE = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class ClassifiedFile:
    path: Path
    host: str
    size_bytes: int
    kind: str | None  # None => unrecognized, reported explicitly rather than dropped


def discover_and_classify(sources: list[SourceSpec]) -> list[ClassifiedFile]:
    seen: dict[Path, ClassifiedFile] = {}
    for spec in sources:
        root = spec.path.resolve()
        if not root.exists():
            raise FileNotFoundError(f"source path does not exist: {root}")
        host = spec.host or root.name or str(root)

        candidates = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]

        for p in candidates:
            if p.suffix.lower() in _SKIP_SUFFIXES:
                continue
            resolved = p.resolve()
            if resolved in seen:
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size == 0 or size > _MAX_CANDIDATE_SIZE:
                continue
            kind = classify_file(resolved)
            seen[resolved] = ClassifiedFile(path=resolved, host=host, size_bytes=size, kind=kind)

    return list(seen.values())


__all__ = ["ClassifiedFile", "discover_and_classify", "sha256_file"]
