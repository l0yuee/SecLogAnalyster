"""Orchestrates discovery and parallel staging for the non-EVTX log families
(Scheduled Tasks, web/Exchange/Linux/database logs, Tencent Cloud Host
Security logs, and Registry hives). Runs as a second pass alongside the existing EVTX ingest (see
case.py), over the same `--source` inputs. Per-table Parquet flattening is
delegated to flatten.py, mirroring how the EVTX pipeline
(`ingest/evtx/orchestrator.py` + `ingest/evtx/flatten.py`) splits the two
responsibilities.

Each worker stages its parsed rows to a per-file NDJSON file on disk (same
pattern as the EVTX pipeline) instead of returning them in-memory --
flatten.py then reads every table's staged files via DuckDB, out-of-core,
rather than the coordinator accumulating every row of a batch in Python
first. This matters in practice: these formats were originally assumed
low per-file record volume, but web access/error logs in particular can
reach far larger scale in real evidence sets (see
docs/known_limitations.md), so unbounded in-memory accumulation across a
whole ingest batch was a real cost, not just a theoretical one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from ...distributed.config import ClusterConfig
from ...distributed.queue import INGEST_QUEUE_NAME, get_job_queue
from ..common import SourceSpec, StageStatus
from ..jobs import PHASE_FLATTENING, PHASE_STAGING, ProgressReporter
from .discovery import ClassifiedFile, discover_and_classify
from .flatten import flatten_table
from .manifest import AuxIngestReport, AuxStagedFile
from .stage import stage_aux_file


def run_aux_ingest(
    case_dir: Path,
    sources: list[SourceSpec],
    workers: int | None = None,
    keep_staging: bool = True,
    cluster_config: ClusterConfig | None = None,
    classified: list[ClassifiedFile] | None = None,
    progress: ProgressReporter | None = None,
) -> AuxIngestReport:
    cluster_config = cluster_config or ClusterConfig.from_env()
    batch_id = str(uuid.uuid4())
    if classified is None:
        # Not pre-scanned by Case.ingest() (e.g. called directly, as
        # existing tests do) -- discover on our own, exactly as before.
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

    staging_dir = case_dir / "staging_aux"
    staging_dir.mkdir(parents=True, exist_ok=True)

    if progress:
        progress.set_phase(PHASE_STAGING)

    # Unknown files require no hashing or parsing. Materialize their tiny
    # report entries locally instead of paying one process-pool / distributed
    # queue round trip per file. Real software acquisition trees commonly
    # contain tens of thousands of binaries beside only a few dozen logs.
    unknown_classified = [cf for cf in classified if cf.kind is None]
    staged: list[AuxStagedFile] = []
    for cf in unknown_classified:
        f = stage_aux_file(cf, staging_dir)
        staged.append(f)
        if progress:
            progress.on_aux_result(f)

    known_classified = [cf for cf in classified if cf.kind is not None]
    if known_classified:
        # Distributed mode: staging_dir must be reachable by every `seclogx
        # worker` process (a shared/NFS mount), same requirement as the EVTX
        # pipeline's staging_dir -- see ingest/evtx/orchestrator.py.
        queue = get_job_queue(cluster_config, workers=workers, queue_name=INGEST_QUEUE_NAME)
        on_result = progress.on_aux_result if progress else None
        staged.extend(
            queue.submit_all(stage_aux_file, [(cf, staging_dir) for cf in known_classified], on_result=on_result)
        )
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

    by_table: dict[str, list[str]] = {}
    for f in staged:
        if f.table and f.ndjson_path:
            by_table.setdefault(f.table, []).append(f.ndjson_path)

    if progress:
        progress.set_phase(PHASE_FLATTENING)
    ingested_at = datetime.now(timezone.utc)
    rows_written: dict[str, int] = {}
    for table, ndjson_paths in by_table.items():
        rows = flatten_table(case_dir, table, ndjson_paths, batch_id, ingested_at, cluster_config=cluster_config)
        rows_written[table] = rows
        if progress:
            progress.on_table_flattened(table, rows)

    if not keep_staging:
        for f in staged:
            if f.ndjson_path:
                Path(f.ndjson_path).unlink(missing_ok=True)

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
