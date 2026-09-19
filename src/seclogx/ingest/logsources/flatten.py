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
from contextlib import ExitStack
from pathlib import Path

import duckdb

from ..resources import CONVERSION_LOCK, IngestOptions
from ..arrow_staging import arrow_reader

from ...distributed.config import ClusterConfig
from ...distributed.storage import ensure_hive_partition_dirs, get_storage_backend
from .partitioning import PartitionRow
from .schema import TABLES, cast_sql_for


def build_select_query(table: str, batch_id: str, ingested_at: datetime, from_sql: str) -> str:
    """Apply the same canonical casts and run metadata to staged or live Arrow."""
    overrides = {
        "ingest_batch_id": "'" + batch_id.replace("'", "''") + "'",
        "ingested_at": f"TIMESTAMP '{ingested_at.strftime('%Y-%m-%d %H:%M:%S.%f')}'",
        "schema_version": "1",
    }
    casts = cast_sql_for(table)
    expressions = [
        f"{overrides[col] if col in overrides else casts[col]} AS {col}"
        for col, _ in TABLES[table]["columns"]
    ]
    return "SELECT " + ",\n  ".join(expressions) + " " + from_sql


def flatten_table(
    case_dir: Path,
    table: str,
    ndjson_paths: list[str],
    batch_id: str,
    ingested_at: datetime,
    cluster_config: ClusterConfig | None = None,
    options: IngestOptions | None = None,
    *,
    partition_rows: list[PartitionRow] | None = None,
) -> int:
    if not ndjson_paths:
        return 0

    table_def = TABLES[table]
    backend = get_storage_backend(cluster_config or ClusterConfig.from_env())
    lake_location = backend.table_location(case_dir, table)
    backend.ensure_dir(lake_location)

    options = options or IngestOptions()
    with CONVERSION_LOCK, duckdb.connect() as con, ExitStack() as inputs:
        options.configure_connection(con)
        backend.configure_duckdb(con)

        paths_sql = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in ndjson_paths) + "]"
        # Read normalized fields as text before applying the canonical casts.
        # Automatic inference can interpret a timestamp-shaped message/user
        # name as TIMESTAMP in one shard, changing its original spelling when
        # cast back to VARCHAR. Fixed input types also make missing fields
        # NULL consistently across sparse batches. Parser catchalls (extra,
        # fields, actions, ...) are already JSON-serialized strings.
        input_columns = "{" + ", ".join(f"'{col}': 'VARCHAR'" for col, _ in table_def["columns"]) + "}"
        from_sql = f"FROM read_ndjson({paths_sql}, columns={input_columns}) AS raw"
        is_arrow = [Path(path).suffix == ".arrow" for path in ndjson_paths]
        if any(is_arrow) and not all(is_arrow):
            raise ValueError("a conversion batch cannot mix Arrow and NDJSON staging")

        def bind_arrow() -> None:
            # RecordBatchReaders are single-pass. A legacy manifest fallback
            # may need a separate reader for partition discovery and COPY.
            inputs.close()
            reader = inputs.enter_context(arrow_reader(ndjson_paths, [col for col, _ in table_def["columns"]]))
            con.register("staged_arrow", reader)

        if all(is_arrow):
            bind_arrow()
            from_sql = "FROM staged_arrow AS raw"

        partition_columns = table_def["partition_by"]
        partition_by = ", ".join(partition_columns)
        select_query = build_select_query(table, batch_id, ingested_at, from_sql)

        # DuckDB creates Hive partition directories as part of COPY. Two
        # concurrent writers targeting the same new partition can race on
        # Windows, where the losing CreateDirectory call is an error. Python's
        # mkdir(exist_ok=True) handles this race, so initialize the finite set of
        # partitions before COPY there. New manifests carry a bounded complete
        # partition list, avoiding a second full pass over staged files.
        # None retains the authoritative scan for legacy/unsupported metadata.
        # Backends without this race need neither path.
        if backend.precreates_partition_dirs:
            if partition_rows is None:
                partition_rows = con.execute(f"SELECT DISTINCT {partition_by} FROM ({select_query})").fetchall()
                if all(is_arrow):
                    bind_arrow()
            ensure_hive_partition_dirs(backend, lake_location, partition_columns, partition_rows)

        (row_count,) = con.execute(
            f"""
            COPY (
              {select_query}
            ) TO '{backend.copy_target(lake_location)}' (
              FORMAT PARQUET, COMPRESSION ZSTD, COMPRESSION_LEVEL 1,
              PARTITION_BY ({partition_by}), OVERWRITE_OR_IGNORE true, FILENAME_PATTERN '{{uuid}}'
            )
            """
        ).fetchone()
        return int(row_count)
