from __future__ import annotations

import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from ..discovery import SourceSpec, discover_evtx_files
from ..errors import NoSourcesFoundError
from .flatten import flatten_case
from .manifest import IngestReport, StagedFile, StageStatus, now_iso
from .stage import stage_file


def run_ingest(
    case_dir: Path,
    case_name: str,
    sources: list[SourceSpec],
    workers: int | None = None,
    keep_raw: bool = False,
    keep_staging: bool = True,
) -> IngestReport:
    started_at = now_iso()
    batch_id = str(uuid.uuid4())

    discovered = discover_evtx_files(sources)
    if not discovered:
        raise NoSourcesFoundError("no .evtx files found under the given source path(s)")

    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    staged_files: list[StagedFile] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(stage_file, d, staging_dir, keep_raw) for d in discovered]
        for fut in as_completed(futures):
            staged_files.append(fut.result())

    # Deterministic ordering for reproducible reports/logs.
    staged_files.sort(key=lambda f: f.source_path)

    records_staged = sum(f.record_count for f in staged_files)
    files_ok = sum(1 for f in staged_files if f.status == StageStatus.OK)
    files_partial = sum(1 for f in staged_files if f.status == StageStatus.PARTIAL)
    files_failed = sum(1 for f in staged_files if f.status == StageStatus.FAILED)

    records_flattened = flatten_case(case_dir, staged_files, batch_id, keep_raw=keep_raw)

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
    log_path.write_text(report.summary_text())

    return report
