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

from ...distributed.config import ClusterConfig
from ...distributed.storage import get_storage_backend
from .schema import TABLES, cast_sql_for


def flatten_table(
    case_dir: Path,
    table: str,
    rows: list[dict],
    batch_id: str,
    ingested_at: datetime,
    cluster_config: ClusterConfig | None = None,
) -> int:
    if not rows:
        return 0

    table_def = TABLES[table]
    backend = get_storage_backend(cluster_config or ClusterConfig.from_env())
    lake_location = backend.table_location(case_dir, table)
    backend.ensure_dir(lake_location)

    con = duckdb.connect()
    backend.configure_duckdb(con)
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
        ) TO '{backend.copy_target(lake_location)}' (
          FORMAT PARQUET, PARTITION_BY ({partition_by}), OVERWRITE_OR_IGNORE true, FILENAME_PATTERN '{{uuid}}'
        )
        """
    )
    con.close()
    return len(df)
