"""Orchestrates discovery and parallel staging for the non-EVTX log families
(Scheduled Tasks, web/Exchange/Linux/database logs, Tencent Cloud Host
Security logs, and Registry hives). Runs as a second pass alongside the existing EVTX ingest (see
case.py), over the same `--source` inputs. Per-table Parquet flattening is
delegated to flatten.py, mirroring how the EVTX pipeline
(`ingest/evtx/orchestrator.py` + `ingest/evtx/flatten.py`) splits the two
responsibilities.

Workers write bounded NDJSON or Arrow shards rather than returning parsed
rows in memory. Automatic local direct conversion handles supported native
web sources sequentially after the ordinary staging queue has shut down;
those published Parquet files bypass the later staged-file conversion.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ...distributed.config import ClusterConfig
from ...distributed.queue import INGEST_QUEUE_NAME, get_job_queue
from ..common import SourceSpec, StageStatus
from ..jobs import PHASE_FLATTENING, PHASE_STAGING, ProgressReporter
from ..resources import IngestOptions
from ..staging import staged_batches, remove_staged
from .discovery import ClassifiedFile, discover_and_classify
from .flatten import flatten_table
from .manifest import AuxIngestReport, AuxStagedFile
from .sniff import KIND_IIS, KIND_WEB_ACCESS
from .stage import stage_aux_file


def run_aux_ingest(
    case_dir: Path,
    sources: list[SourceSpec],
    workers: int | None = None,
    keep_staging: bool = False,
    cluster_config: ClusterConfig | None = None,
    classified: list[ClassifiedFile] | None = None,
    progress: ProgressReporter | None = None,
    options: IngestOptions | None = None,
) -> AuxIngestReport:
    options = options or IngestOptions()
    cluster_config = cluster_config or ClusterConfig.from_env()
    options = options.resolve_execution(keep_staging=keep_staging, cluster_config=cluster_config)
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

    staging_dir = case_dir / "staging_aux" / batch_id
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

    use_direct = options.direct_parquet and any(cf.kind in (KIND_WEB_ACCESS, KIND_IIS) for cf in classified)
    if use_direct and options.parser_backend == "auto":
        # If the extension is unavailable, retain the ordinary worker queue
        # for all formats rather than replaying web files one at a time in
        # the coordinator. Workers record the normal fallback reason.
        from .native import load_native_component

        use_direct = load_native_component().module is not None
    direct_classified = []
    known_classified = []
    for cf in classified:
        if use_direct and cf.kind in (KIND_WEB_ACCESS, KIND_IIS):
            direct_classified.append(cf)
        elif cf.kind is not None:
            known_classified.append(cf)
    if known_classified:
        # Distributed mode: staging_dir must be reachable by every `seclogx
        # worker` process (a shared/NFS mount), same requirement as the EVTX
        # pipeline's staging_dir -- see ingest/evtx/orchestrator.py.
        queue = get_job_queue(cluster_config, workers=workers, queue_name=INGEST_QUEUE_NAME)
        on_result = progress.on_aux_result if progress else None
        staged.extend(
            queue.submit_all(stage_aux_file, [(cf, staging_dir, options) for cf in known_classified], on_result=on_result)
        )

    # submit_all returns only after the local staging pool has closed. Direct
    # conversion therefore uses one lane without reducing the ordinary worker
    # budget or overlapping it with another auxiliary conversion connection.
    # The helper shares CONVERSION_LOCK with the EVTX/staged conversion paths.
    ingested_at = datetime.now(timezone.utc)
    rows_written: dict[str, int] = {}
    if direct_classified:
        from .direct import direct_web_file

        if progress:
            progress.set_phase(PHASE_FLATTENING)
        fallback_options = replace(options, parser_backend="python", direct_parquet=False)
        for cf in direct_classified:
            direct = direct_web_file(cf, case_dir, batch_id, ingested_at, options)
            f = direct.staged_file
            if f is None:
                # A compatibility replay must use the same verified source
                # identity and encoding, and must not attempt native parsing
                # again after the direct reader has rejected this source.
                if direct.prepared is None:
                    from .native import NativeBatchError

                    raise NativeBatchError(f"direct fallback lacks prepared source identity: {cf.path}")
                f = stage_aux_file(cf, staging_dir, fallback_options, prepared=direct.prepared)
                f.backend_reason = direct.fallback_reason
            elif direct.parquet_path is not None and f.table:
                rows_written[f.table] = rows_written.get(f.table, 0) + direct.rows_written
                if progress:
                    progress.on_table_flattened(f.table, direct.rows_written)
            staged.append(f)
            if progress:
                progress.on_aux_result(f)
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

    by_table: dict[tuple[str, bool], list[AuxStagedFile]] = {}
    for f in staged:
        if f.output_format == "staged" and f.table and f.ndjson_path:
            # Auto mode can select different staging formats for files in
            # the same table. Each conversion stream must be homogeneous.
            by_table.setdefault((f.table, Path(f.ndjson_path).suffix == ".arrow"), []).append(f)

    if progress:
        progress.set_phase(PHASE_FLATTENING)
    for (table, _), files in by_table.items():
        rows_written.setdefault(table, 0)
        for batch in staged_batches(files, options.flatten_batch_bytes):
            paths = [f.ndjson_path for f in batch]
            partitions = None
            if all(f.partition_rows is not None for f in batch):
                unique_partitions = set()
                for f in batch:
                    unique_partitions.update(f.partition_rows)
                    if len(unique_partitions) > 4096:
                        break
                else:
                    partitions = list(unique_partitions)
            rows = flatten_table(case_dir, table, paths, batch_id, ingested_at,
                                 cluster_config=cluster_config, options=options, partition_rows=partitions)
            rows_written[table] += rows
            if progress:
                progress.on_table_flattened(table, rows)

    if not keep_staging:
        for f in staged:
            if f.output_format == "staged":
                remove_staged(f)

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
