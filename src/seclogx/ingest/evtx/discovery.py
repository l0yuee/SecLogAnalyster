"""Discover .evtx files across one or more (possibly unrelated) source paths.

`discover_evtx_files()` is a thin wrapper over `ingest.scan.scan_sources()`,
which walks each `--source` root exactly once and buckets files for *both*
the EVTX and non-EVTX (aux) pipelines in a single pass -- see that module.
This module keeps its own public function/dataclass so every existing
direct caller and test is unaffected.
"""

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
    # Deferred import: ingest.scan imports DiscoveredFile from this module,
    # so importing it back at module load time would be circular.
    from ..scan import scan_sources

    return scan_sources(sources).evtx_files
