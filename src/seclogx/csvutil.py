"""Shared bounded-memory CSV export: stream a chunked query result
straight to disk, one chunk at a time, never holding more than one chunk
in memory. Used by both the CLI (`cli/_render.py`) and the plain-language
search interface (`search.py`) so the logic lives in exactly one place."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pandas as pd


def export_chunks_to_csv(chunks: Iterator[pd.DataFrame], path: Path) -> int:
    """Write every chunk to `path` as CSV, streaming. Returns the total
    row count written."""
    total = 0
    header_written = False
    with open(path, "w", newline="") as f:
        for chunk in chunks:
            chunk.to_csv(f, index=False, header=not header_written)
            header_written = True
            total += len(chunk)
    if not header_written:
        open(path, "w").close()
    return total
