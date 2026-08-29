"""Orchestrates discovery, parallel staging, and Parquet-lake flattening for
the non-EVTX log families (Scheduled Tasks, IIS/nginx/Apache/Tomcat web
access AND error logs, Exchange CSV logs). Runs as a second pass alongside
the existing EVTX ingest (see case.py), over the same `--source` inputs.

Unlike the EVTX pipeline (NDJSON staging + one bulk DuckDB flatten, chosen
because per-record Python marshaling was the bottleneck at EVTX's typical
record volume), these formats are already line-oriented text or small XML
files at far lower per-file record counts, so each worker parses straight
to Python dicts and this module batches them directly into Parquet -- no
intermediate staging files needed.
"""

from __future__ import annotations

import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd

from ..discovery import SourceSpec
from .discovery import discover_and_classify
from .manifest import AuxIngestReport, AuxStagedFile, StageStatus, now_iso
from .schema import TABLES, cast_sql_for
from .stage import stage_aux_file


def run_aux_ingest(case_dir: Path, sources: list[SourceSpec], workers: int | None = None) -> AuxIngestReport:
    batch_id = str(uuid.uuid4())
    classified = discover_and_classify(sources)

    if not classified:
        return AuxIngestReport(
            batch_id=batch_id,
            files_discovered=0,
            files_ok=0,
            files_partial=0,
            files_failed=0,
            files_unknown=0,
            unknown_samples=[],
            rows_written={},
            problem_files=[],
        )

    staged: list[AuxStagedFile] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(stage_aux_file, cf) for cf in classified]
        for fut in as_completed(futures):
            staged.append(fut.result())
    staged.sort(key=lambda f: f.source_path)

    files_ok = sum(1 for f in staged if f.status == StageStatus.OK)
    files_partial = sum(1 for f in staged if f.status == StageStatus.PARTIAL)
    files_failed = sum(1 for f in staged if f.status == StageStatus.FAILED)
    unknown_files = [f for f in staged if f.status == StageStatus.UNKNOWN]
    problem_files = [
        (f.source_path, f.status, f.error_message or "")
        for f in staged
        if f.status in (StageStatus.PARTIAL, StageStatus.FAILED)
    ]

    by_table: dict[str, list[dict]] = {}
    for f in staged:
        if f.table and f.rows:
            by_table.setdefault(f.table, []).extend(f.rows)

    ingested_at = datetime.now(timezone.utc)
    rows_written = {table: _flatten_table(case_dir, table, rows, batch_id, ingested_at) for table, rows in by_table.items()}

    return AuxIngestReport(
        batch_id=batch_id,
        files_discovered=len(classified),
        files_ok=files_ok,
        files_partial=files_partial,
        files_failed=files_failed,
        files_unknown=len(unknown_files),
        unknown_samples=[f.source_path for f in unknown_files],
        rows_written=rows_written,
        problem_files=problem_files,
        staged_files=staged,
    )


def _flatten_table(case_dir: Path, table: str, rows: list[dict], batch_id: str, ingested_at: datetime) -> int:
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
