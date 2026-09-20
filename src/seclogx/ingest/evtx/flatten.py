"""Bulk-flatten staged NDJSON into the case's normalized Parquet lake.

Deliberately does the flattening as one set-based DuckDB SQL statement over
all staged files at once, rather than per-record Python transformation --
this is the fast path validated during design (the `evtx` package's real
bottleneck is per-record Python marshaling, not parsing).

Field-level extraction is defined once in schema.py (EXTRACTION_SQL) and
reused here; this module's job is wiring provenance (host/source file/
ingest batch) via a join against the staging manifest, and the
partitioned COPY.
"""

from __future__ import annotations

from datetime import datetime, timezone
from contextlib import ExitStack, contextmanager
from pathlib import Path

import duckdb
import pyarrow as pa

from ..resources import CONVERSION_LOCK, IngestOptions
import pandas as pd

from ...distributed.config import ClusterConfig
from ...paths import duckdb_path
from ...distributed.storage import ensure_hive_partition_dirs, get_storage_backend
from ...schema import CORE_COLUMNS, EXTRACTION_SQL
from .manifest import StagedFile
from ..arrow_staging import iter_arrow_batches


@contextmanager
def _arrow_with_filename(files: list[StagedFile], columns):
    schema = pa.schema([(name, pa.string()) for name in columns])
    output_schema = schema.append(pa.field("filename", pa.string()))

    def batches():
        for file in files:
            source = iter_arrow_batches([file.ndjson_path], schema)
            try:
                for batch in source:
                    yield batch.append_column("filename", pa.repeat(duckdb_path(file.ndjson_path), batch.num_rows))
            finally:
                source.close()

    source = batches()
    reader = pa.RecordBatchReader.from_batches(output_schema, source)
    try:
        yield reader
    finally:
        try:
            reader.close()
        finally:
            source.close()


def flatten_case(
    case_dir: Path,
    staged_files: list[StagedFile],
    batch_id: str,
    keep_raw: bool = False,
    cluster_config: ClusterConfig | None = None,
    options: IngestOptions | None = None,
) -> int:
    """Flatten all successfully-staged NDJSON files into the case's Parquet lake.

    Returns the number of rows written (0 if there was nothing to flatten).
    """
    ok_files = [f for f in staged_files if f.ndjson_path]
    if not ok_files:
        return 0
    arrow_files = [f for f in ok_files if Path(f.ndjson_path).suffix == ".arrow"]
    if arrow_files and len(arrow_files) != len(ok_files):
        # Separate raw formats while retaining a single conversion budget.
        ndjson_files = [f for f in ok_files if Path(f.ndjson_path).suffix != ".arrow"]
        return sum(flatten_case(case_dir, group, batch_id, keep_raw, cluster_config, options)
                   for group in (arrow_files, ndjson_files))

    backend = get_storage_backend(cluster_config or ClusterConfig.from_env())
    lake_location = backend.table_location(case_dir, "events")
    backend.ensure_dir(lake_location)

    ingested_at = datetime.now(timezone.utc)

    options = options or IngestOptions()
    with CONVERSION_LOCK, duckdb.connect() as con, ExitStack() as inputs:
        options.configure_connection(con)
        backend.configure_duckdb(con)
        manifest_df = pd.DataFrame(
            [
                {
                    "ndjson_path": duckdb_path(f.ndjson_path),
                    "host": f.host,
                    "source_path": f.source_path,
                    "source_file": f.source_file,
                    "file_sha256": f.file_sha256,
                }
                for f in ok_files
            ]
        )
        con.register("manifest_df", manifest_df)

        raw_columns = {"event_record_id": "BIGINT", "timestamp": "VARCHAR", "data": "VARCHAR"}
        if keep_raw:
            raw_columns["raw_xml"] = "VARCHAR"
        raw_columns_sql = "{" + ", ".join(f"'{k}': '{v}'" for k, v in raw_columns.items()) + "}"
        ndjson_paths_sql = "[" + ", ".join("'" + duckdb_path(f.ndjson_path).replace("'", "''") + "'"
                                         for f in ok_files) + "]"

        overrides = {
            "host": "m.host",
            "source_path": "m.source_path",
            "source_file": "m.source_file",
            "file_sha256": "m.file_sha256",
            "ingest_batch_id": "'" + batch_id.replace("'", "''") + "'",
            "ingested_at": f"TIMESTAMP '{ingested_at.strftime('%Y-%m-%d %H:%M:%S.%f')}'",
            "raw_xml": "raw.raw_xml" if keep_raw else "NULL::VARCHAR",
        }

        select_exprs = []
        for col, _, _ in CORE_COLUMNS:
            expr = overrides[col] if col in overrides else EXTRACTION_SQL[col]
            if col == "record_id" and arrow_files:
                expr = "CAST(raw.event_record_id AS BIGINT)"
            select_exprs.append(f"{expr} AS {col}")
        select_sql = ",\n  ".join(select_exprs)

        from_sql = f"""
        FROM read_ndjson({ndjson_paths_sql}, columns={raw_columns_sql}, filename=true) AS raw
        JOIN manifest_df m ON raw.filename = m.ndjson_path
        """

        def bind_arrow():
            inputs.close()
            reader = inputs.enter_context(_arrow_with_filename(ok_files, raw_columns))
            con.register("evtx_staged_arrow", reader)

        if arrow_files:
            bind_arrow()
            from_sql = "FROM evtx_staged_arrow AS raw JOIN manifest_df m ON raw.filename = m.ndjson_path"

        select_query = f"SELECT {select_sql} {from_sql}"
        # Windows-only concurrent-CreateDirectory workaround; enumerating the
        # partitions is a second full pass over every staged record, so it's
        # skipped where the race doesn't exist -- see
        # StorageBackend.precreates_partition_dirs and logsources/flatten.py.
        partition_columns = ("host", "channel")
        if backend.precreates_partition_dirs:
            partition_rows = con.execute(
                f"SELECT DISTINCT {', '.join(partition_columns)} FROM ({select_query})"
            ).fetchall()
            if arrow_files:
                bind_arrow()
            ensure_hive_partition_dirs(backend, lake_location, partition_columns, partition_rows)

        destination = duckdb_path(backend.copy_target(lake_location)).replace("'", "''")
        (row_count,) = con.execute(
            f"""
            COPY (
              {select_query}
            ) TO '{destination}' (
              FORMAT PARQUET, COMPRESSION ZSTD, COMPRESSION_LEVEL 1,
              PARTITION_BY (host, channel), OVERWRITE_OR_IGNORE true, FILENAME_PATTERN '{{uuid}}'
            )
            """
        ).fetchone()

        expected = sum(f.record_count for f in ok_files)
        if row_count != expected:
            raise RuntimeError(f"EVTX conversion integrity failure: staged {expected} records but wrote {row_count}")
        return int(row_count)
