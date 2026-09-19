"""Serializable resource settings shared by ingest coordinators and workers."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, replace
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

    ``parser_backend`` defaults to ``auto``: supported auxiliary sources use
    native batch parsing with Python compatibility fallback. ``python`` and
    ``native`` are diagnostic overrides. EVTX uses its existing parser.

    ``direct_parquet=None`` automatically streams supported local web sources
    into Parquet when staging is not retained. Explicit True requires local
    execution/storage, a native-capable backend and ``keep_staging=False``;
    False forces staging. Conversions share the coordinator's memory budget.
    """

    memory_limit: str = "2GB"
    threads: int = 2
    staging_chunk_bytes: int = 64 * 1024 * 1024
    flatten_batch_bytes: int = 256 * 1024 * 1024
    # Auxiliary text/artifact staging only; EVTX keeps its raw JSON contract.
    staging_format: str = "auto"
    # Native parsers preserve the same canonical table contract.
    parser_backend: str = "auto"
    # None selects the path from the execution context, without caller tuning.
    direct_parquet: bool | None = None

    def __post_init__(self) -> None:
        if self.direct_parquet is not None and not isinstance(self.direct_parquet, bool):
            raise ValueError("direct_parquet must be a boolean or None")
        if self.direct_parquet and self.parser_backend == "python":
            raise ValueError("direct_parquet requires parser_backend='auto' or 'native'")
        if self.parser_backend not in ("auto", "python", "native"):
            raise ValueError("parser_backend must be 'auto', 'python' or 'native'")
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

    def validate_execution(self, *, keep_staging: bool, cluster_config: Any) -> None:
        """Reject incompatible direct-output settings before starting work."""
        if not self.direct_parquet:
            return
        if keep_staging:
            raise ValueError("direct_parquet requires keep_staging=False")
        if cluster_config.is_distributed or cluster_config.storage_backend != "local":
            raise ValueError("direct_parquet requires local execution and local storage")

    def resolve_execution(self, *, keep_staging: bool, cluster_config: Any) -> IngestOptions:
        """Resolve the automatic output path once at an ingest boundary.

        Explicit requests retain their validation errors. Automatic mode
        adapts to retention, storage and execution requirements without
        asking an analyst to configure a different parser pipeline.
        """
        self.validate_execution(keep_staging=keep_staging, cluster_config=cluster_config)
        if self.direct_parquet is not None:
            return self
        return replace(self, direct_parquet=(
            not keep_staging
            and not cluster_config.is_distributed
            and cluster_config.storage_backend == "local"
            and self.parser_backend != "python"
        ))
