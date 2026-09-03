"""Where the Parquet lake lives: `StorageBackend` abstracts the handful
of filesystem-shaped operations `CaseDB`/`Case`/the flatten functions
need over `<case>/lake/`, so that directory can be a local path (default,
`LocalStorageBackend`) or an `s3://` prefix on shared object storage
(`S3StorageBackend`, opt-in via `SECLOGX_STORAGE_BACKEND=s3`).

Deliberately scoped to just the lake (the queryable Parquet payload,
which distributed ingest workers write into concurrently and multiple
analysts read concurrently) -- `case.json` and `staging/` stay on the
case's local/NFS-mounted directory in every mode. They're small,
coordinator-only, ingest-time bookkeeping, not the thing that needs to
scale or be reachable from every worker; see `locking.py` for how
concurrent writers to `case.json` are kept safe instead.

DuckDB itself remains the only query engine -- this module never
distributes a *query*, only tells DuckDB where to find/write files. See
`ClusterConfig`'s docstring and docs/architecture.md for that scope
boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from pathlib import Path
from urllib.parse import quote, unquote

import duckdb

from ..errors import ClusterConfigError
from .config import ClusterConfig


class StorageBackend(ABC):
    """One case's Parquet lake, addressed relative to `case_dir`. Every
    method after `lake_location`/`table_location` takes the string a
    prior call on this backend returned -- callers never construct these
    locations themselves."""

    def lake_location(self, case_dir: Path) -> str:
        """Root location of this case's lake (`<case_dir>/lake` locally,
        or an `s3://` prefix keyed by the case's name)."""
        raise NotImplementedError

    def table_location(self, case_dir: Path, table: str) -> str:
        return self.join(self.lake_location(case_dir), table)

    @abstractmethod
    def join(self, location: str, *parts: str) -> str: ...

    @abstractmethod
    def exists(self, location: str) -> bool: ...

    @abstractmethod
    def ensure_dir(self, location: str) -> None:
        """Make sure `location` is writable as a COPY target. A no-op for
        object storage, which has no directories to create."""

    @abstractmethod
    def table_dirs(self, lake_location: str) -> list[str]:
        """Names of the table subdirectories directly under the lake
        root (e.g. `events`, `web_logs`, ...) -- mirrors
        `CaseDB.__init__`'s original `lake_dir.iterdir()` scan."""

    @abstractmethod
    def has_parquet(self, table_location: str) -> bool: ...

    @abstractmethod
    def host_partitions(self, table_location: str) -> set[str]:
        """Percent-decoded values of this table's `host=<value>` Hive
        partitions -- mirrors `_hosts_from_lake`'s original
        `table_dir.glob("host=*")` scan."""

    @abstractmethod
    def parquet_glob(self, table_location: str) -> str:
        """String to hand DuckDB's `read_parquet(...)`."""

    @abstractmethod
    def copy_target(self, table_location: str) -> str:
        """String to hand a `COPY ... TO '<this>'` statement."""

    def configure_duckdb(self, con: duckdb.DuckDBPyConnection) -> None:
        """Prepare a fresh DuckDB connection to read/write this backend's
        locations. A no-op locally; installs+configures `httpfs` for S3."""


class LocalStorageBackend(StorageBackend):
    """Exactly today's behavior: plain `pathlib` operations against the
    local (or NFS-mounted, from a POSIX point of view indistinguishable)
    `<case_dir>/lake/` directory. Every existing test exercises this path
    and must see identical behavior to before this module existed."""

    def lake_location(self, case_dir: Path) -> str:
        return str(Path(case_dir) / "lake")

    def join(self, location: str, *parts: str) -> str:
        return str(Path(location).joinpath(*parts))

    def exists(self, location: str) -> bool:
        return Path(location).exists()

    def ensure_dir(self, location: str) -> None:
        Path(location).mkdir(parents=True, exist_ok=True)

    def table_dirs(self, lake_location: str) -> list[str]:
        root = Path(lake_location)
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir() if p.is_dir())

    def has_parquet(self, table_location: str) -> bool:
        return any(Path(table_location).rglob("*.parquet"))

    def host_partitions(self, table_location: str) -> set[str]:
        table_dir = Path(table_location)
        if not table_dir.exists():
            return set()
        return {unquote(p.name[len("host=") :]) for p in table_dir.glob("host=*") if p.is_dir()}

    def parquet_glob(self, table_location: str) -> str:
        return str(Path(table_location) / "**" / "*.parquet")

    def copy_target(self, table_location: str) -> str:
        return table_location


class S3StorageBackend(StorageBackend):
    """Lake stored under `s3://<bucket>/<case name>/lake/...`. Metadata
    listing (which tables/partitions exist) goes through boto3, since
    that's cheap prefix/delimiter listing that doesn't need a DuckDB
    connection; the actual Parquet read/write goes through DuckDB's
    built-in `httpfs` extension, configured with credentials resolved via
    boto3's standard credential chain (never stored in `ClusterConfig`
    itself -- see its docstring)."""

    def __init__(self, cluster_config: ClusterConfig):
        try:
            import boto3
        except ImportError as e:  # pragma: no cover - exercised only when boto3 missing
            raise ClusterConfigError(
                "SECLOGX_STORAGE_BACKEND=s3 requires the 'cluster' extra: pip install 'seclogx[cluster]'"
            ) from e
        if not cluster_config.s3_bucket:
            raise ClusterConfigError("SECLOGX_STORAGE_BACKEND=s3 requires SECLOGX_S3_BUCKET to be set")
        self.cluster_config = cluster_config
        self.bucket = cluster_config.s3_bucket
        self._session = boto3.Session()
        self._client = self._session.client(
            "s3",
            endpoint_url=cluster_config.s3_endpoint_url,
            region_name=cluster_config.s3_region,
        )

    def _key(self, location: str) -> str:
        prefix = f"s3://{self.bucket}/"
        if not location.startswith(prefix):
            raise ClusterConfigError(f"not an s3://{self.bucket}/... location: {location!r}")
        return location[len(prefix) :]

    def lake_location(self, case_dir: Path) -> str:
        case_name = Path(case_dir).name
        return f"s3://{self.bucket}/{case_name}/lake"

    def join(self, location: str, *parts: str) -> str:
        return "/".join([location.rstrip("/"), *parts])

    def exists(self, location: str) -> bool:
        key = self._key(location).rstrip("/") + "/"
        resp = self._client.list_objects_v2(Bucket=self.bucket, Prefix=key, MaxKeys=1)
        return resp.get("KeyCount", 0) > 0

    def ensure_dir(self, location: str) -> None:
        pass  # object storage has no directories to create

    def table_dirs(self, lake_location: str) -> list[str]:
        prefix = self._key(lake_location).rstrip("/") + "/"
        resp = self._client.list_objects_v2(Bucket=self.bucket, Prefix=prefix, Delimiter="/")
        return sorted(p["Prefix"][len(prefix) : -1] for p in resp.get("CommonPrefixes", []))

    def has_parquet(self, table_location: str) -> bool:
        prefix = self._key(table_location).rstrip("/") + "/"
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                if obj["Key"].endswith(".parquet"):
                    return True
        return False

    def host_partitions(self, table_location: str) -> set[str]:
        prefix = self._key(table_location).rstrip("/") + "/"
        paginator = self._client.get_paginator("list_objects_v2")
        hosts: set[str] = set()
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            for p in page.get("CommonPrefixes", []):
                name = p["Prefix"][len(prefix) : -1]
                if name.startswith("host="):
                    hosts.add(unquote(name[len("host=") :]))
        return hosts

    def parquet_glob(self, table_location: str) -> str:
        return table_location.rstrip("/") + "/**/*.parquet"

    def copy_target(self, table_location: str) -> str:
        return table_location

    def configure_duckdb(self, con: duckdb.DuckDBPyConnection) -> None:
        con.execute("INSTALL httpfs")
        con.execute("LOAD httpfs")
        creds = self._session.get_credentials()
        if creds is not None:
            frozen = creds.get_frozen_credentials()
            con.execute("SET s3_access_key_id=?", [frozen.access_key])
            con.execute("SET s3_secret_access_key=?", [frozen.secret_key])
            if frozen.token:
                con.execute("SET s3_session_token=?", [frozen.token])
        if self.cluster_config.s3_region:
            con.execute("SET s3_region=?", [self.cluster_config.s3_region])
        if self.cluster_config.s3_endpoint_url:
            endpoint = self.cluster_config.s3_endpoint_url.split("://", 1)[-1]
            con.execute("SET s3_endpoint=?", [endpoint])
            con.execute("SET s3_use_ssl=?", [self.cluster_config.s3_endpoint_url.startswith("https://")])
            con.execute("SET s3_url_style='path'")  # required by MinIO and most non-AWS S3-compatible stores


def ensure_hive_partition_dirs(
    backend: StorageBackend,
    table_location: str,
    columns: Sequence[str],
    rows: Iterable[Sequence[object]],
) -> None:
    """Pre-create local Hive partition directories before DuckDB COPY.

    Concurrent DuckDB COPY statements can race while creating the same
    partition directory on Windows. ``Path.mkdir(exist_ok=True)`` handles
    that race correctly, while S3's ``ensure_dir`` remains a no-op.
    """
    for row in rows:
        parts = []
        for column, value in zip(columns, row, strict=True):
            encoded = "__HIVE_DEFAULT_PARTITION__" if value is None else quote(str(value), safe="")
            parts.append(f"{column}={encoded}")
        backend.ensure_dir(backend.join(table_location, *parts))


def get_storage_backend(cluster_config: ClusterConfig | None = None) -> StorageBackend:
    cluster_config = cluster_config or ClusterConfig.from_env()
    if cluster_config.is_s3:
        return S3StorageBackend(cluster_config)
    return LocalStorageBackend()
