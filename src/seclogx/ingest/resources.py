"""Serializable resource settings shared by ingest coordinators and workers."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from decimal import Decimal
from typing import Any


_MEMORY_LIMIT = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)", re.IGNORECASE)

# Serialize conversions in one coordinator (including Notebook) process;
# parsing can continue in worker processes within its separate budget.
CONVERSION_LOCK = threading.Lock()


@dataclass(frozen=True)
class IngestOptions:
    """Bound the work performed by each ingest conversion instance.

    ``memory_limit`` configures DuckDB's managed memory for one connection;
    it is not a hard limit on process RSS, parser memory, or concurrent
    conversions. Chunk sizes are byte targets, so a single large record
    can exceed ``staging_chunk_bytes``.
    """

    memory_limit: str = "2GB"
    threads: int = 2
    staging_chunk_bytes: int = 64 * 1024 * 1024
    flatten_batch_bytes: int = 256 * 1024 * 1024
    # Auxiliary text/artifact staging only; EVTX keeps its raw JSON contract.
    staging_format: str = "auto"

    def __post_init__(self) -> None:
        if self.staging_format not in ("auto", "ndjson", "arrow"):
            raise ValueError("staging_format must be 'auto', 'ndjson' or 'arrow'")
        match = _MEMORY_LIMIT.fullmatch(self.memory_limit.strip()) if isinstance(self.memory_limit, str) else None
        if match is None or Decimal(match.group(1)) <= 0:
            raise ValueError("memory_limit must be a positive size with a unit, for example '512MB' or '2GB'")
        object.__setattr__(self, "memory_limit", f"{match.group(1)}{match.group(2).upper()}")
        for name in ("threads", "staging_chunk_bytes", "flatten_batch_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def configure_connection(self, con: Any) -> None:
        """Apply per-connection limits before a DuckDB conversion begins."""
        # Both interpolated values have been strictly validated above.
        con.execute(f"SET memory_limit = '{self.memory_limit}'")
        con.execute(f"SET threads = {self.threads}")
        con.execute("SET preserve_insertion_order = false")
