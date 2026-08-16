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
from pathlib import Path

import duckdb
import pandas as pd

from ..schema import CORE_COLUMNS, EXTRACTION_SQL
from .manifest import StagedFile


def flatten_case(case_dir: Path, staged_files: list[StagedFile], batch_id: str, keep_raw: bool = False) -> int:
    """Flatten all successfully-staged NDJSON files into the case's Parquet lake.

    Returns the number of rows written (0 if there was nothing to flatten).
    """
    ok_files = [f for f in staged_files if f.ndjson_path]
    if not ok_files:
        return 0

    lake_dir = case_dir / "lake"
    lake_dir.mkdir(parents=True, exist_ok=True)

    ingested_at = datetime.now(timezone.utc)

    con = duckdb.connect()
    manifest_df = pd.DataFrame(
        [
            {
                "ndjson_path": f.ndjson_path,
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
    ndjson_paths_sql = "[" + ", ".join("'" + f.ndjson_path.replace("'", "''") + "'" for f in ok_files) + "]"

    overrides = {
        "host": "m.host",
        "source_path": "m.source_path",
        "source_file": "m.source_file",
        "file_sha256": "m.file_sha256",
        "ingest_batch_id": f"'{batch_id}'",
        "ingested_at": f"TIMESTAMP '{ingested_at.strftime('%Y-%m-%d %H:%M:%S.%f')}'",
        "raw_xml": "raw.raw_xml" if keep_raw else "NULL::VARCHAR",
    }

    select_exprs = []
    for col, _, _ in CORE_COLUMNS:
        expr = overrides[col] if col in overrides else EXTRACTION_SQL[col]
        select_exprs.append(f"{expr} AS {col}")
    select_sql = ",\n  ".join(select_exprs)

    from_sql = f"""
    FROM read_ndjson({ndjson_paths_sql}, columns={raw_columns_sql}, filename=true) AS raw
    JOIN manifest_df m ON raw.filename = m.ndjson_path
    """

    (row_count,) = con.execute(f"SELECT count(*) {from_sql}").fetchone()
    if row_count == 0:
        return 0

    con.execute(
        f"""
        COPY (
          SELECT
          {select_sql}
          {from_sql}
        ) TO '{lake_dir}' (FORMAT PARQUET, PARTITION_BY (host, channel), OVERWRITE_OR_IGNORE true)
        """
    )

    return int(row_count)
