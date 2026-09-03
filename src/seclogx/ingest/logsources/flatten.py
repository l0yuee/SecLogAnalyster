"""Flatten one non-EVTX log table's staged NDJSON files into the case's
Parquet lake. Mirrors `ingest/evtx/flatten.py`'s role for the EVTX
pipeline, at per-table rather than whole-batch granularity (see
orchestrator.py, which calls this once per table present in a given
ingest batch), and the same "read via DuckDB straight off disk, don't
materialize the whole table in Python first" approach -- every aux row
already carries its own `host` (unlike EVTX's raw NDJSON records), so no
manifest-join is needed here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb

from ...distributed.config import ClusterConfig
from ...distributed.storage import ensure_hive_partition_dirs, get_storage_backend
from .schema import TABLES, cast_sql_for


def flatten_table(
    case_dir: Path,
    table: str,
    ndjson_paths: list[str],
    batch_id: str,
    ingested_at: datetime,
    cluster_config: ClusterConfig | None = None,
) -> int:
    if not ndjson_paths:
        return 0

    table_def = TABLES[table]
    backend = get_storage_backend(cluster_config or ClusterConfig.from_env())
    lake_location = backend.table_location(case_dir, table)
    backend.ensure_dir(lake_location)

    con = duckdb.connect()
    backend.configure_duckdb(con)

    paths_sql = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in ndjson_paths) + "]"
    # union_by_name: different staged files for the same table can have
    # slightly different key sets (e.g. an Exchange log variant with extra
    # '#Fields:' columns) -- union rather than requiring identical schemas.
    from_sql = f"FROM read_ndjson_auto({paths_sql}, union_by_name=true) AS raw"

    cast_sql = cast_sql_for(table)
    overrides = {
        "ingest_batch_id": f"'{batch_id}'",
        "ingested_at": f"TIMESTAMP '{ingested_at.strftime('%Y-%m-%d %H:%M:%S.%f')}'",
        "schema_version": "1",
    }
    # Columns DuckDB actually inferred from this batch's staged files -- a
    # column every parser can emit but that happens to be absent from
    # every row in this particular batch (e.g. no Exchange log variant
    # with a given optional field) won't be in `raw`'s schema at all.
    raw_columns = set(con.sql(f"SELECT * {from_sql}").columns)

    select_exprs = []
    for col, duckdb_type in table_def["columns"]:
        if col in overrides:
            expr = overrides[col]
        else:
            # A column absent from every staged file for this batch isn't
            # in DuckDB's inferred schema for `raw`; fall back to NULL
            # rather than referencing a column that doesn't exist.
            expr = f"CAST(NULL AS {duckdb_type})" if col not in raw_columns else cast_sql[col]
        select_exprs.append(f"{expr} AS {col}")
    select_sql = ",\n  ".join(select_exprs)

    partition_columns = table_def["partition_by"]
    partition_by = ", ".join(partition_columns)
    select_query = f"SELECT {select_sql} {from_sql}"

    # DuckDB creates Hive partition directories as part of COPY. Two
    # concurrent writers targeting the same new partition can race on
    # Windows, where the losing CreateDirectory call is an error. Python's
    # mkdir(exist_ok=True) handles this race, so initialize the finite set of
    # partitions before COPY; this is a no-op for object storage.
    partition_rows = con.execute(f"SELECT DISTINCT {partition_by} FROM ({select_query})").fetchall()
    ensure_hive_partition_dirs(backend, lake_location, partition_columns, partition_rows)

    (row_count,) = con.execute(
        f"""
        COPY (
          {select_query}
        ) TO '{backend.copy_target(lake_location)}' (
          FORMAT PARQUET, PARTITION_BY ({partition_by}), OVERWRITE_OR_IGNORE true, FILENAME_PATTERN '{{uuid}}'
        )
        """
    ).fetchone()
    con.close()
    return int(row_count)
