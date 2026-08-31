"""Thin DuckDB wrapper over a case's Parquet lake.

Primary interface is `.sql()` -- deliberately no query-builder DSL beyond
a handful of convenience methods for the most common lookups. DuckDB
handles the lazy/out-of-core execution and predicate pushdown over the
Hive-partitioned Parquet lake, but `.sql()`/`.table()` still materialize
the *entire* result as one pandas DataFrame via `.fetchdf()` -- fine for
a filtered/aggregated result, but any of these log families can
realistically reach terabyte scale (web access/error logs especially),
at which point one in-memory DataFrame for a whole table is the actual
bottleneck, not the query engine. `.sql_chunks()`/`.table_chunks()` are
the bounded-memory alternative: an iterator of DataFrame chunks, each
independently small (bounded by `chunksize`, not by total result size),
using DuckDB's `fetch_df_chunk()` rather than `fetchdf()`. Verified
empirically: reading 5M rows via chunks added ~190MB of peak RSS,
against ~2.7GB for `fetchdf()` on the same query -- the difference is
bounded vs. proportional-to-data-size memory use, which is what actually
matters at real-world log volumes.

The lake is organized as one table per log family under `lake/<table>/`
(`events` for Windows Event Log; `web_logs`, `web_error_logs`,
`scheduled_tasks`, `exchange_message_tracking`, `exchange_logs` for the
other artifact types -- see ingest/logsources/schema.py). A view is created per
subdirectory found, so a case only ever exposes tables it actually has
data for, and a new log family only needs a lake subdirectory to become
queryable here -- true for both the eager and chunked accessors.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import duckdb
import pandas as pd

from .distributed.config import ClusterConfig
from .distributed.storage import get_storage_backend
from .memcheck import available_memory_bytes

# DuckDB's internal vector size (rows per execution batch) -- fetch_df_chunk()
# takes a count of these, not a row count, so user-facing `chunksize` (rows)
# is translated via this constant.
_DUCKDB_VECTOR_SIZE = 2048
DEFAULT_CHUNKSIZE = 100_000

# When available system memory can't be determined at all (memcheck.py
# returns None), fall back to this absolute cap rather than either
# blocking everything or assuming unlimited memory.
_UNKNOWN_MEMORY_FALLBACK_BYTES = 200 * 1024 * 1024


@dataclass
class ResultSizeEstimate:
    """How big a query's result is expected to be, estimated cheaply:
    `count(*)` for the row count (a streaming aggregate, not a
    materialization) plus a small sample (`LIMIT sample_rows`) to get
    pandas' actual (deep, including string/object overhead) bytes-per-row,
    extrapolated to the full row count. Both steps are bounded regardless
    of the table's total size, so estimating is itself memory-safe."""

    row_count: int
    estimated_bytes: int
    sampled_rows: int

    def fits_in_memory(self, safety_fraction: float = 0.25) -> bool:
        """Whether materializing this result as one DataFrame is safe,
        judged against a fraction of currently available system memory
        (default: no more than a quarter of it) -- leaves headroom for
        pandas' own transformation overhead and everything else running on
        the analyst's machine, not just the raw DataFrame bytes. Falls
        back to an absolute cap if available memory can't be determined at
        all, rather than assuming unlimited memory."""
        available = available_memory_bytes()
        budget = available * safety_fraction if available is not None else _UNKNOWN_MEMORY_FALLBACK_BYTES
        return self.estimated_bytes <= budget


class CaseDB:
    def __init__(self, case_dir: Path, cluster_config: ClusterConfig | None = None):
        self.case_dir = Path(case_dir)
        self.cluster_config = cluster_config or ClusterConfig.from_env()
        self.backend = get_storage_backend(self.cluster_config)
        self.lake_dir = self.backend.lake_location(self.case_dir)
        self._con = duckdb.connect()
        self.backend.configure_duckdb(self._con)
        self.tables: list[str] = []
        # search.py's per-table "which columns hold a JSON object" detection
        # is content-sniffed (see there for why), not free -- cached here so
        # it only runs once per table per CaseDB instance, not once per
        # condition. Invalidated naturally whenever Case creates a fresh
        # CaseDB (post-ingest).
        self._json_object_columns_cache: dict[str, list[str]] = {}
        if self.backend.exists(self.lake_dir):
            for table_name in sorted(self.backend.table_dirs(self.lake_dir)):
                table_location = self.backend.join(self.lake_dir, table_name)
                if not self.backend.has_parquet(table_location):
                    continue
                glob = self.backend.parquet_glob(table_location)
                self._con.execute(
                    f"CREATE VIEW {table_name} AS "
                    f"SELECT * FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)"
                )
                self.tables.append(table_name)
        self._has_data = "events" in self.tables

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        """Escape hatch for anything the convenience methods don't cover."""
        return self._con

    def _require_data(self) -> None:
        if not self.tables:
            raise RuntimeError(f"case at {self.case_dir} has no ingested data yet -- run `ingest` first")

    def _require_events(self) -> None:
        if not self._has_data:
            raise RuntimeError(
                f"case at {self.case_dir} has no ingested Windows Event Log data "
                "(other tables may still be queryable via .sql(), see .tables)"
            )

    def sql(self, query: str, params: list | None = None) -> pd.DataFrame:
        self._require_data()
        return self._con.execute(query, params or []).fetchdf()

    def sql_chunks(
        self, query: str, params: list | None = None, chunksize: int = DEFAULT_CHUNKSIZE
    ) -> Iterator[pd.DataFrame]:
        """Bounded-memory alternative to `.sql()`: yields the result as a
        series of DataFrames of about `chunksize` rows each, instead of one
        DataFrame holding the entire result. Use this for any query that
        isn't already filtered/aggregated down to something that
        comfortably fits in memory -- see the module docstring.

        Runs on its own cursor (`self._con.cursor()`), not the shared
        connection, so this can be iterated concurrently with other
        `.sql()`/`.sql_chunks()` calls on the same CaseDB without one
        resetting the other's result cursor."""
        self._require_data()
        vectors_per_chunk = max(1, chunksize // _DUCKDB_VECTOR_SIZE)
        cursor = self._con.cursor()
        cursor.execute(query, params or [])
        while True:
            chunk = cursor.fetch_df_chunk(vectors_per_chunk)
            if chunk.empty:
                return
            yield chunk

    def estimate(self, query: str, params: list | None = None, sample_rows: int = 2000) -> ResultSizeEstimate:
        """Cheaply estimate a query's result size before deciding whether
        to fetch it eagerly -- see `ResultSizeEstimate`. Used by
        `search.py` to refuse an eager fetch that would risk exhausting
        memory and point the caller at a chunked/streamed alternative
        instead."""
        self._require_data()
        (row_count,) = self._con.execute(f"SELECT count(*) FROM ({query}) AS _estimate", params or []).fetchone()
        if row_count == 0:
            return ResultSizeEstimate(row_count=0, estimated_bytes=0, sampled_rows=0)
        sample = self._con.execute(
            f"SELECT * FROM ({query}) AS _estimate LIMIT {int(sample_rows)}", params or []
        ).fetchdf()
        bytes_per_row = (sample.memory_usage(deep=True).sum() / len(sample)) if len(sample) else 0
        return ResultSizeEstimate(
            row_count=row_count, estimated_bytes=int(bytes_per_row * row_count), sampled_rows=len(sample)
        )

    def table(self, name: str, order_by: str | None = None) -> pd.DataFrame:
        """Full contents of any table this case has (see `.tables`) as a
        DataFrame -- the same uniform escape hatch `events` gets via
        `summary()`/`by_host()`/etc., generalized to every log family so a
        new one never needs a CaseDB change to become DataFrame-accessible.
        Returns an empty DataFrame (not an error) if the case has no data
        for this table -- consistent with `hosts()`/`channels()`.

        For a table that may be very large, prefer `.table_chunks()`."""
        if name not in self.tables:
            return pd.DataFrame()
        order = f" ORDER BY {order_by}" if order_by else ""
        return self.sql(f"SELECT * FROM {name}{order}")

    def table_chunks(
        self, name: str, order_by: str | None = None, chunksize: int = DEFAULT_CHUNKSIZE
    ) -> Iterator[pd.DataFrame]:
        """Bounded-memory alternative to `.table()` -- see `.sql_chunks()`.
        Yields nothing (not an error) if the case has no data for this
        table, consistent with `.table()` returning an empty DataFrame."""
        if name not in self.tables:
            return
        order = f" ORDER BY {order_by}" if order_by else ""
        yield from self.sql_chunks(f"SELECT * FROM {name}{order}", chunksize=chunksize)

    def by_time(self, start=None, end=None, host: str | None = None, channel: str | None = None) -> pd.DataFrame:
        conds, params = [], []
        if start is not None:
            conds.append("time_created >= ?")
            params.append(start)
        if end is not None:
            conds.append("time_created <= ?")
            params.append(end)
        if host is not None:
            conds.append("host = ?")
            params.append(host)
        if channel is not None:
            conds.append("channel = ?")
            params.append(channel)
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        return self.sql(f"SELECT * FROM events {where} ORDER BY time_created", params)

    def by_event_id(self, event_id: int | list[int], channel: str | None = None) -> pd.DataFrame:
        ids = event_id if isinstance(event_id, (list, tuple)) else [event_id]
        placeholders = ",".join("?" for _ in ids)
        params = list(ids)
        where = f"WHERE event_id IN ({placeholders})"
        if channel is not None:
            where += " AND channel = ?"
            params.append(channel)
        return self.sql(f"SELECT * FROM events {where} ORDER BY time_created", params)

    def by_host(self, host: str) -> pd.DataFrame:
        return self.sql("SELECT * FROM events WHERE host = ? ORDER BY time_created", [host])

    def by_channel(self, channel: str) -> pd.DataFrame:
        return self.sql("SELECT * FROM events WHERE channel = ? ORDER BY time_created", [channel])

    def search(self, text: str) -> pd.DataFrame:
        """Free-text search across event_data, provider, and computer fields."""
        pattern = f"%{text}%"
        return self.sql(
            "SELECT * FROM events WHERE CAST(event_data AS VARCHAR) ILIKE ? "
            "OR provider_name ILIKE ? OR computer ILIKE ? ORDER BY time_created",
            [pattern, pattern, pattern],
        )

    def summary(self) -> pd.DataFrame:
        return self.sql(
            "SELECT host, channel, event_id, count(*) AS count, "
            "min(time_created) AS first_seen, max(time_created) AS last_seen "
            "FROM events GROUP BY host, channel, event_id ORDER BY count DESC"
        )

    def table_counts(self) -> pd.DataFrame:
        """Row count per table currently in the case (events, web_logs,
        scheduled_tasks, exchange_message_tracking, exchange_logs -- whichever
        are present). Use to see at a glance what log families a case has."""
        if not self.tables:
            return pd.DataFrame(columns=["table", "rows"])
        rows = [
            {"table": t, "rows": self._con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]} for t in self.tables
        ]
        return pd.DataFrame(rows)

    def hosts(self) -> list[str]:
        if not self._has_data:
            return []
        rows = self._con.execute("SELECT DISTINCT host FROM events").fetchall()
        return sorted((r[0] for r in rows), key=lambda x: (x is None, x))

    def channels(self) -> list[str]:
        if not self._has_data:
            return []
        rows = self._con.execute("SELECT DISTINCT channel FROM events").fetchall()
        return sorted((r[0] for r in rows), key=lambda x: (x is None, x))

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> "CaseDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
