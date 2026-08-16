"""Thin DuckDB wrapper over a case's Parquet lake.

Primary interface is `.sql()` -- deliberately no query-builder DSL beyond
a handful of convenience methods for the most common lookups. DuckDB
handles the lazy/out-of-core execution and predicate pushdown over the
Hive-partitioned Parquet lake; every method here returns a pandas
DataFrame, since that's the point of integration with the analyst's
existing pandas workflow.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd


class CaseDB:
    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.lake_dir = self.case_dir / "lake"
        self._con = duckdb.connect()
        self._has_data = any(self.lake_dir.rglob("*.parquet")) if self.lake_dir.exists() else False
        if self._has_data:
            glob = str(self.lake_dir / "**" / "*.parquet")
            self._con.execute(
                f"CREATE VIEW events AS SELECT * FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)"
            )

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        """Escape hatch for anything the convenience methods don't cover."""
        return self._con

    def _require_data(self) -> None:
        if not self._has_data:
            raise RuntimeError(f"case at {self.case_dir} has no ingested data yet -- run `ingest` first")

    def sql(self, query: str, params: list | None = None) -> pd.DataFrame:
        self._require_data()
        return self._con.execute(query, params or []).fetchdf()

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
