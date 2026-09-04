"""Discover and classify non-.evtx files under the same `--source` inputs
used for EVTX discovery. Conceptually a second pass over the same source
trees (`.evtx` files are skipped -- those stay owned by the existing EVTX
pipeline), so one `--source` covers every supported artifact type.

`discover_and_classify()` is now a thin wrapper over `ingest.scan.scan_sources()`,
which walks each `--source` root exactly once and buckets files for *both*
pipelines in a single pass (see that module for why: two independent
single-threaded tree walks over a large evidence set was real, measured
wall-clock cost, not just a theoretical one). This module keeps its own
public functions/dataclass so every existing direct caller and test is
unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..common import MAX_CANDIDATE_SIZE as _MAX_CANDIDATE_SIZE
from ..common import SKIP_SUFFIXES as _SKIP_SUFFIXES
from ..common import SourceSpec, sha256_file


@dataclass(frozen=True)
class ClassifiedFile:
    path: Path
    host: str
    size_bytes: int
    kind: str | None  # None => unrecognized, reported explicitly rather than dropped


def discover_and_classify(sources: list[SourceSpec]) -> list[ClassifiedFile]:
    # Deferred import: ingest.scan imports ClassifiedFile from this module,
    # so importing it back at module load time would be circular.
    from ..scan import scan_sources

    return scan_sources(sources).aux_files


__all__ = ["ClassifiedFile", "discover_and_classify", "sha256_file"]
