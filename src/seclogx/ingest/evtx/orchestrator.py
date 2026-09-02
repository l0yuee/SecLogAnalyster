from __future__ import annotations

import uuid
from pathlib import Path

from ...distributed.config import ClusterConfig
from ...distributed.queue import INGEST_QUEUE_NAME, get_job_queue
from ...errors import NoSourcesFoundError
from ..common import SourceSpec, StageStatus, now_iso
from .discovery import discover_evtx_files
from .flatten import flatten_case
from .manifest import IngestReport, StagedFile
from .stage import stage_file


def run_ingest(
    case_dir: Path,
    case_name: str,
    sources: list[SourceSpec],
    workers: int | None = None,
    keep_raw: bool = False,
    keep_staging: bool = True,
    cluster_config: ClusterConfig | None = None,
) -> IngestReport:
    cluster_config = cluster_config or ClusterConfig.from_env()
    started_at = now_iso()
    batch_id = str(uuid.uuid4())

    discovered = discover_evtx_files(sources)
    if not discovered:
        raise NoSourcesFoundError("no .evtx files found under the given source path(s)")

    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    # Distributed mode (cluster_config.is_distributed): one `stage_file`
    # task per discovered .evtx file is enqueued for `seclogx worker`
    # processes to pick up -- staging_dir must then be reachable from
    # every worker (a shared/NFS mount), same as it's always been
    # reachable from this coordinator process. Local mode (default):
    # identical ProcessPoolExecutor behavior as before this module existed.
    queue = get_job_queue(cluster_config, workers=workers, queue_name=INGEST_QUEUE_NAME)
    staged_files: list[StagedFile] = queue.submit_all(stage_file, [(d, staging_dir, keep_raw) for d in discovered])

    # Deterministic ordering for reproducible reports/logs.
    staged_files.sort(key=lambda f: f.source_path)

    records_staged = sum(f.record_count for f in staged_files)
    files_ok = sum(1 for f in staged_files if f.status == StageStatus.OK)
    files_partial = sum(1 for f in staged_files if f.status == StageStatus.PARTIAL)
    files_failed = sum(1 for f in staged_files if f.status == StageStatus.FAILED)

    records_flattened = flatten_case(case_dir, staged_files, batch_id, keep_raw=keep_raw, cluster_config=cluster_config)

    if not keep_staging:
        for f in staged_files:
            if f.ndjson_path:
                Path(f.ndjson_path).unlink(missing_ok=True)

    report = IngestReport(
        batch_id=batch_id,
        case_name=case_name,
        started_at=started_at,
        finished_at=now_iso(),
        files_discovered=len(discovered),
        files_ok=files_ok,
        files_partial=files_partial,
        files_failed=files_failed,
        records_staged=records_staged,
        records_flattened=records_flattened,
        staged_files=staged_files,
    )

    log_path = case_dir / "logs" / f"ingest_{batch_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # encoding="utf-8" is explicit: source paths/error messages embedded in
    # the summary can carry non-ASCII content from the evidence itself, and
    # write_text()'s default encoding otherwise follows the OS locale (e.g.
    # GBK/cp936 on Chinese-locale Windows), which can't represent everything.
    log_path.write_text(report.summary_text(), encoding="utf-8")

    return report
