"""Thin DuckDB wrapper over a case's Parquet lake.

Primary interface is `.sql()` -- deliberately no query-builder DSL beyond
a handful of convenience methods for the most common lookups. DuckDB
handles the lazy/out-of-core execution and predicate pushdown over the
Hive-partitioned Parquet lake; every method here returns a pandas
DataFrame, since that's the point of integration with the analyst's
existing pandas workflow.

The lake is organized as one table per log family under `lake/<table>/`
(`events` for Windows Event Log; `web_logs`, `scheduled_tasks`,
`exchange_message_tracking`, `exchange_logs` for the other artifact types
-- see logsources/schema.py). A view is created per subdirectory found, so
a case only ever exposes tables it actually has data for, and a new log
family only needs a lake subdirectory to become queryable here.
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
        self.tables: list[str] = []
        if self.lake_dir.exists():
            for table_dir in sorted(p for p in self.lake_dir.iterdir() if p.is_dir()):
                if not any(table_dir.rglob("*.parquet")):
                    continue
                glob = str(table_dir / "**" / "*.parquet")
                self._con.execute(
                    f"CREATE VIEW {table_dir.name} AS "
                    f"SELECT * FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)"
                )
                self.tables.append(table_dir.name)
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

    def table(self, name: str, order_by: str | None = None) -> pd.DataFrame:
        """Full contents of any table this case has (see `.tables`) as a
        DataFrame -- the same uniform escape hatch `events` gets via
        `summary()`/`by_host()`/etc., generalized to every log family so a
        new one never needs a CaseDB change to become DataFrame-accessible.
        Returns an empty DataFrame (not an error) if the case has no data
        for this table -- consistent with `hosts()`/`channels()`."""
        if name not in self.tables:
            return pd.DataFrame()
        order = f" ORDER BY {order_by}" if order_by else ""
        return self.sql(f"SELECT * FROM {name}{order}")

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
