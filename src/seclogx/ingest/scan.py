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
import stat as statmod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .common import MAX_CANDIDATE_SIZE, SKIP_SUFFIXES, SourceSpec
from .evtx.discovery import DiscoveredFile
from .logsources.discovery import ClassifiedFile
from .logsources.sniff import classify_file

# Classification is I/O-bound (a bounded read per file) rather than
# CPU-bound, so a higher-than-core-count thread pool is appropriate --
# capped so a source tree with an enormous file count doesn't open
# thousands of file descriptors at once.
_MAX_CLASSIFY_WORKERS = 32

# How often the walk reports its running file count. The walk is the first
# thing an ingest does and, on a large acquisition tree, the part that used
# to look like a hang; reporting every file would be its own overhead, so
# batch it.
_WALK_REPORT_INTERVAL = 500


@dataclass(frozen=True)
class ScanResult:
    evtx_files: list[DiscoveredFile]
    aux_files: list[ClassifiedFile]


def _walk_files(root: Path) -> Iterator[tuple[Path, os.stat_result]]:
    """Every regular file under `root`, with the stat already taken.

    `os.scandir` rather than `Path.rglob("*")` + `is_file()` + `resolve()`
    + `stat()`: the latter costs three or four syscalls per file (plus
    `resolve()`'s per-path-component readlink walk), where scandir gets the
    type from the directory read itself and needs one stat. Measured ~15x
    faster on a 2,300-file tree with a warm cache, and the gap widens on
    cold/network/spinning storage where syscall count dominates.

    Symlink handling matches what `rglob`/`is_file()` did before: symlinked
    *directories* are not descended into (no cycles), while a symlink to a
    file is followed and yielded as a file."""
    if root.is_file():
        try:
            yield root, root.stat()
        except OSError:
            return
        return

    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            # Unreadable directory (permissions, a race with the acquisition
            # tool, a dead mount): skip it rather than aborting the ingest.
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                    continue
                # follow_symlinks=True (the default): a symlink pointing at
                # a real log file is still that log file, and stat'ing the
                # target is also what gives dedup its identity below.
                st = entry.stat()
            except OSError:
                continue
            if statmod.S_ISREG(st.st_mode):
                yield Path(entry.path), st


def _identity(path: Path, st: os.stat_result) -> object:
    """A key identifying one physical file, for cross-source dedup.

    `(st_dev, st_ino)` where the platform reports them: that dedups the
    same file reached through two overlapping `--source` roots exactly as
    the old `resolve()`-keyed dict did, also catches hard links, and comes
    free from a stat the walk already has to do.

    On Windows, `os.DirEntry.stat()` documents `st_ino`/`st_dev` as always
    zero (they aren't in the data the directory scan returns), which would
    otherwise collapse every file onto one key and drop the entire
    acquisition after the first file. There we fall back to the resolved
    path -- the pre-existing behavior, and correct, just not free."""
    if st.st_ino:
        return (st.st_dev, st.st_ino)
    try:
        return path.resolve()
    except OSError:
        return path


def scan_sources(
    sources: list[SourceSpec],
    on_scanned: Callable[[int], None] | None = None,
    on_walked: Callable[[int], None] | None = None,
) -> ScanResult:
    """Walk every `--source` root exactly once, bucketing each file as an
    EVTX candidate (by extension -- no content read needed) or an aux
    candidate (peeked and classified by content, matching
    `logsources.discovery.discover_and_classify`'s prior rules exactly:
    same skip-suffix set, same size ceiling, same cross-source dedup).

    `on_walked` is called during the walk with a running count of files
    seen so far (batched, see `_WALK_REPORT_INTERVAL`); `on_scanned` is
    called with a running total of aux files *classified* so far. The
    caller is responsible for throttling how often it acts on either (see
    `ingest.jobs.ProgressReporter`)."""
    # Keyed by file identity -- see `_identity`.
    evtx_seen: dict[object, DiscoveredFile] = {}
    aux_seen: dict[object, tuple[Path, str, int]] = {}
    walked = 0

    for spec in sources:
        root = spec.path.resolve()
        if not root.exists():
            raise FileNotFoundError(f"source path does not exist: {root}")
        host = spec.host or root.name or str(root)

        for path, st in _walk_files(root):
            walked += 1
            if on_walked is not None and walked % _WALK_REPORT_INTERVAL == 0:
                on_walked(walked)

            identity = _identity(path, st)
            suffix = path.suffix.lower()

            if suffix == ".evtx":
                if identity not in evtx_seen:
                    evtx_seen[identity] = DiscoveredFile(path=path, host=host, size_bytes=st.st_size)
                continue

            if suffix in SKIP_SUFFIXES or identity in aux_seen:
                continue
            if st.st_size == 0 or st.st_size > MAX_CANDIDATE_SIZE:
                continue
            aux_seen[identity] = (path, host, st.st_size)

    if on_walked is not None and walked:
        on_walked(walked)

    aux_files: list[ClassifiedFile] = []
    items = list(aux_seen.values())
    if items:
        workers = min(_MAX_CLASSIFY_WORKERS, max(1, (os.cpu_count() or 1) * 4))

        def _classify(entry: tuple[Path, str, int]) -> ClassifiedFile:
            path, host, size = entry
            return ClassifiedFile(path=path, host=host, size_bytes=size, kind=classify_file(path))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for scanned, cf in enumerate(pool.map(_classify, items), start=1):
                aux_files.append(cf)
                if on_scanned is not None:
                    on_scanned(scanned)

    return ScanResult(evtx_files=list(evtx_seen.values()), aux_files=aux_files)


__all__ = ["ScanResult", "scan_sources"]
