"""Optional distributed/cluster-mode support -- a job queue for fanning
ingest and Sigma-hunt work across worker processes/machines, plus a
storage backend abstraction so the Parquet lake can live on shared object
storage instead of local disk.

Every piece here is opt-in and resolved from environment variables (see
`config.ClusterConfig.from_env()`); nothing in this package is imported
by default code paths unless a broker/S3 backend is actually configured,
so plain single-machine use (the default) is unaffected.
"""

from __future__ import annotations

from .config import ClusterConfig

__all__ = ["ClusterConfig"]
