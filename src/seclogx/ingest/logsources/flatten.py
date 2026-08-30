"""Flatten one non-EVTX log table's in-memory rows into the case's Parquet
lake. Mirrors `ingest/evtx/flatten.py`'s role for the EVTX pipeline, at
per-table rather than whole-batch granularity (see orchestrator.py, which
calls this once per table present in a given ingest batch).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb
import pandas as pd

from .schema import TABLES, cast_sql_for


def flatten_table(case_dir: Path, table: str, rows: list[dict], batch_id: str, ingested_at: datetime) -> int:
    if not rows:
        return 0

    table_def = TABLES[table]
    lake_dir = case_dir / "lake" / table
    lake_dir.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    df = pd.DataFrame(rows)
    con.register("raw", df)

    cast_sql = cast_sql_for(table)
    overrides = {
        "ingest_batch_id": f"'{batch_id}'",
        "ingested_at": f"TIMESTAMP '{ingested_at.strftime('%Y-%m-%d %H:%M:%S.%f')}'",
        "schema_version": "1",
    }

    select_exprs = []
    for col, duckdb_type in table_def["columns"]:
        if col in overrides:
            expr = overrides[col]
        elif col in df.columns:
            expr = cast_sql[col]
        else:
            expr = f"CAST(NULL AS {duckdb_type})"
        select_exprs.append(f"{expr} AS {col}")
    select_sql = ",\n  ".join(select_exprs)

    partition_by = ", ".join(table_def["partition_by"])
    con.execute(
        f"""
        COPY (
          SELECT
          {select_sql}
          FROM raw
        ) TO '{lake_dir}' (FORMAT PARQUET, PARTITION_BY ({partition_by}), OVERWRITE_OR_IGNORE true)
        """
    )
    con.close()
    return len(df)
