"""Cluster/distributed-mode configuration -- resolved from environment
variables so activation requires no new CLI flags on any existing
command. Every value defaults to "local, non-distributed", identical to
seclogx's behavior before this package existed; cluster mode only
engages once SECLOGX_BROKER_URL (job queue) and/or
SECLOGX_STORAGE_BACKEND=s3 (shared object storage) are actually set.

Credentials are deliberately not part of this dataclass -- S3 access goes
through boto3's standard credential chain (env vars / instance profile /
~/.aws/credentials), the same as any other boto3 tool, so nothing secret
is ever read, stored, or logged by seclogx itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ClusterConfig:
    storage_backend: str = "local"  # "local" | "s3"
    s3_bucket: str | None = None
    s3_endpoint_url: str | None = None
    s3_region: str | None = None
    broker_url: str | None = None

    @property
    def is_distributed(self) -> bool:
        """Whether a job queue broker is configured -- ingest/hunt fan out
        across `seclogx worker` processes instead of a local process pool."""
        return bool(self.broker_url)

    @property
    def is_s3(self) -> bool:
        """Whether the Parquet lake lives on S3-compatible object storage
        instead of the local `<case>/lake/` directory."""
        return self.storage_backend == "s3"

    @classmethod
    def local(cls) -> "ClusterConfig":
        """The all-defaults instance -- local storage, no broker. What
        every code path uses unless env vars say otherwise."""
        return cls()

    @classmethod
    def from_env(cls) -> "ClusterConfig":
        return cls(
            storage_backend=os.environ.get("SECLOGX_STORAGE_BACKEND", "local"),
            s3_bucket=os.environ.get("SECLOGX_S3_BUCKET") or None,
            s3_endpoint_url=os.environ.get("SECLOGX_S3_ENDPOINT_URL") or None,
            s3_region=os.environ.get("SECLOGX_S3_REGION") or None,
            broker_url=os.environ.get("SECLOGX_BROKER_URL") or None,
        )

    def redacted(self) -> dict:
        """Safe to print (`seclogx cluster config`) -- there are no
        credential fields on this class to begin with, but kept as one
        stable formatting point in case that ever changes."""
        return {
            "storage_backend": self.storage_backend,
            "s3_bucket": self.s3_bucket,
            "s3_endpoint_url": self.s3_endpoint_url,
            "s3_region": self.s3_region,
            "broker_url": self.broker_url,
            "is_distributed": self.is_distributed,
        }
