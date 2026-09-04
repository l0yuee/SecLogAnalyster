"""Single shared filesystem walk for both ingest pipelines (EVTX and the
non-EVTX log families).

Before this module existed, `Case.ingest()` walked every `--source` tree
*twice*, fully single-threaded each time: once in `ingest/evtx/discovery.py`
to find `.evtx` files, and again in `ingest/logsources/discovery.py` to find
and content-classify everything else. For a real evidence set (thousands of
small/mixed files, some of them not a supported log type at all) that
second pass -- one Python loop, one thread, a 16KB read plus a chain of
regexes per candidate file (`sniff.classify_file`) -- was the dominant
wall-clock cost, and it produced zero visible output the whole time it ran.
`scan_sources()` replaces both walks with one: each root is walked once,
files are bucketed by extension into an EVTX candidate or an aux candidate
needing a content peek, and the aux candidates' peeks (I/O-bound: each is
one `read()` that releases the GIL) are classified in parallel with a
thread pool instead of one at a time.

`discover_evtx_files()`/`discover_and_classify()` (their respective
`ingest/evtx/discovery.py`/`ingest/logsources/discovery.py` modules) are now
thin wrappers over this function, so every existing direct caller keeps its
exact prior behavior; `Case.ingest()` calls this directly so the tree is
only ever walked once per ingest run.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .common import MAX_CANDIDATE_SIZE, SKIP_SUFFIXES, SourceSpec
from .evtx.discovery import DiscoveredFile
from .logsources.discovery import ClassifiedFile
from .logsources.sniff import classify_file

# Classification is I/O-bound (a bounded read per file) rather than
# CPU-bound, so a higher-than-core-count thread pool is appropriate --
# capped so a source tree with an enormous file count doesn't open
# thousands of file descriptors at once.
_MAX_CLASSIFY_WORKERS = 32


@dataclass(frozen=True)
class ScanResult:
    evtx_files: list[DiscoveredFile]
    aux_files: list[ClassifiedFile]


def scan_sources(
    sources: list[SourceSpec],
    on_scanned: Callable[[int], None] | None = None,
) -> ScanResult:
    """Walk every `--source` root exactly once, bucketing each file as an
    EVTX candidate (by extension -- no content read needed) or an aux
    candidate (peeked and classified by content, matching
    `logsources.discovery.discover_and_classify`'s prior rules exactly:
    same skip-suffix set, same size ceiling, same cross-source dedup by
    resolved path). `on_scanned` is called with a running total of aux
    files classified so far; the caller is responsible for throttling how
    often it acts on that (see `ingest.jobs.ProgressReporter`)."""
    evtx_seen: dict[Path, DiscoveredFile] = {}
    aux_seen: dict[Path, tuple[str, int]] = {}

    for spec in sources:
        root = spec.path.resolve()
        if not root.exists():
            raise FileNotFoundError(f"source path does not exist: {root}")
        host = spec.host or root.name or str(root)

        candidates = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]

        for p in candidates:
            resolved = p.resolve()
            suffix = resolved.suffix.lower()

            if suffix == ".evtx":
                if resolved in evtx_seen:
                    continue
                try:
                    size = resolved.stat().st_size
                except OSError:
                    continue
                evtx_seen[resolved] = DiscoveredFile(path=resolved, host=host, size_bytes=size)
                continue

            if suffix in SKIP_SUFFIXES or resolved in aux_seen:
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size == 0 or size > MAX_CANDIDATE_SIZE:
                continue
            aux_seen[resolved] = (host, size)

    aux_files: list[ClassifiedFile] = []
    items = list(aux_seen.items())
    if items:
        workers = min(_MAX_CLASSIFY_WORKERS, max(1, (os.cpu_count() or 1) * 4))
        scanned = 0

        def _classify(entry: tuple[Path, tuple[str, int]]) -> ClassifiedFile:
            resolved, (host, size) = entry
            return ClassifiedFile(path=resolved, host=host, size_bytes=size, kind=classify_file(resolved))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for cf in pool.map(_classify, items):
                aux_files.append(cf)
                scanned += 1
                if on_scanned is not None:
                    on_scanned(scanned)

    return ScanResult(evtx_files=list(evtx_seen.values()), aux_files=aux_files)


__all__ = ["ScanResult", "scan_sources"]
