from __future__ import annotations

import json
import os
from pathlib import Path

import typer
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from ..case import Case
from ..ingest.resources import IngestOptions
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseNotFoundError, NoSourcesFoundError
from ..ingest.common import SourceSpec, now_iso, parse_source_arg
from ..ingest.jobs import job_log_path, read_job_status, validate_job_id
from ..ingest.job_control import JobCancelledError, JobHeartbeat
from ._render import console


def _spawn_background_job(
    case_name: str,
    source: list[str],
    workers: int | None,
    keep_raw: bool,
    keep_staging: bool,
    case_root: Path,
    options: IngestOptions | None = None,
) -> None:
    try:
        c = Case.open(case_name, case_root=case_root)
    except CaseNotFoundError:
        c = Case.create(case_name, case_root=case_root)

    # Case.ingest_background() does the actual detached-subprocess spawn and
    # initial status-file write -- this is the CLI's own front door to it,
    # kept thin so the spawn logic has exactly one implementation.
    job_id = c.ingest_background(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging, options=options)
    log_path = job_log_path(c.case_dir, job_id)

    console.print(f"[green]Started background ingest job {job_id}[/green] for case '{case_name}'")
    console.print(f"  log: {log_path}")
    console.print(f"  check progress: seclogx ingest-status {case_name} {job_id}  (add --watch to follow it)")


def _run_as_background_child(c: Case, job_id: str, case_name: str, source, workers, keep_raw, keep_staging, options=None) -> None:
    validate_job_id(job_id)
    existing = read_job_status(c.case_dir, job_id, reconcile=False) or {}
    initial = {**existing, "job_id": job_id, "case_name": case_name,
               "started_at": existing.get("started_at") or now_iso(), "phase": "scanning"}
    c._background_job_id = job_id
    try:
        with JobHeartbeat(c.case_dir, job_id, initial) as heartbeat:
            report = c.ingest(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging,
                              on_progress=heartbeat.update, options=options)
            # Progress callback failures are deliberately isolated by ingest;
            # make the final durable status write explicit and observable.
            heartbeat.update({"phase": "done", "committed": True, "error": None})
    except JobCancelledError:
        return
    except NoSourcesFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    finally:
        del c._background_job_id

    console.print(report.summary_text())


def _run_in_foreground(c: Case, source, workers, keep_raw, keep_staging, options=None) -> None:
    with Progress(
        TextColumn("[bold]{task.fields[phase]}"),
        BarColumn(),
        TextColumn("{task.fields[detail]}"),
        TimeElapsedColumn(),
        console=console,
    ) as bar:
        task = bar.add_task("ingest", phase="scanning", detail="", total=None)

        def on_progress(snapshot: dict) -> None:
            phase = snapshot.get("phase", "")
            if phase == "scanning":
                walked = snapshot.get("files_walked", 0)
                classified = snapshot.get("files_scanned", 0)
                detail = f"found {walked} files, classified {classified}"
            else:
                staged = snapshot.get("evtx_staged", 0) + snapshot.get("aux_staged", 0)
                discovered = snapshot.get("evtx_discovered", 0) + snapshot.get("aux_discovered", 0)
                detail = (
                    f"staged {staged}/{discovered} "
                    f"(ok {snapshot.get('files_ok', 0)}, partial {snapshot.get('files_partial', 0)}, "
                    f"failed {snapshot.get('files_failed', 0)}, unsupported {snapshot.get('files_unknown', 0)})"
                )
            bar.update(task, phase=phase, detail=detail)

        try:
            report = c.ingest(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging, on_progress=on_progress, options=options)
        except NoSourcesFoundError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)

    console.print(report.summary_text())


def ingest_command(
    case_name: str = typer.Argument(..., help="Case name (created if it doesn't exist)"),
    source: list[str] = typer.Option(
        ...,
        "--source",
        help=(
            "Source path to scan for supported security logs and artifacts, "
            "optionally PATH:HOST. Repeatable."
        ),
    ),
    workers: int | None = typer.Option(None, "--workers", help="Total local parsing workers across both pipelines (default: up to 8)", min=1),
    keep_raw: bool = typer.Option(
        False, "--keep-raw", help="Also capture raw EVTX record XML (adds parsing and storage work; .evtx sources only)"
    ),
    keep_staging: bool = typer.Option(
        False, "--keep-staging/--no-keep-staging", help="Retain temporary staged data after successful conversion (default: remove it)"
    ),
    evtx_ansi_codec: str | None = typer.Option(None, "--evtx-ansi-codec", help="Original Windows code page for EVTX ANSI fields, e.g. gbk; default: windows-1252. Unicode fields are unaffected."),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
    background: bool = typer.Option(
        False,
        "--background",
        "-b",
        help="Run the import detached in the background and return immediately; "
        "check progress with `seclogx ingest-status`",
    ),
    memory_limit: str = typer.Option("2GB", "--memory-limit", help="DuckDB memory per conversion instance; not total process RSS"),
    duckdb_threads: int = typer.Option(2, "--duckdb-threads", min=1),
    staging_chunk_mb: int = typer.Option(64, "--staging-chunk-mb", min=1, help="Uncompressed MiB per staging shard"),
    flatten_batch_mb: int = typer.Option(256, "--flatten-batch-mb", min=1, help="Uncompressed MiB per conversion batch"),
    staging_format: str = typer.Option("auto", "--staging-format", help="EVTX and auxiliary staging: auto (Arrow for sources >=16 MiB), ndjson or arrow"),
    parser_backend: str = typer.Option("auto", "--parser-backend", help="Advanced override: auto selects native parsing with compatibility fallback (default); python or native forces a backend"),
    direct_parquet: bool | None = typer.Option(None, "--direct-parquet/--no-direct-parquet", help="Advanced override: automatically stream supported local sources to Parquet by default; force or disable direct output"),
    _staging_chunk_bytes: int | None = typer.Option(None, "--staging-chunk-bytes", hidden=True, min=1),
    _flatten_batch_bytes: int | None = typer.Option(None, "--flatten-batch-bytes", hidden=True, min=1),
    _job_id: str = typer.Option(None, "--_job-id", hidden=True),
) -> None:
    try:
        if evtx_ansi_codec is not None:
            source = [SourceSpec(spec.path, spec.host, evtx_ansi_codec)
                      for spec in map(parse_source_arg, source)]
        if _job_id is not None:
            validate_job_id(_job_id)
            encoded = os.environ.get("SECLOGX_SOURCE_SPECS")
            if encoded:
                specs = json.loads(encoded)
                if not isinstance(specs, list) or not specs:
                    raise ValueError("invalid background source metadata")
                source = [SourceSpec(Path(spec["path"]), spec.get("host"), spec.get("ansi_codec"))
                          for spec in specs]
        options = IngestOptions(
            memory_limit=memory_limit, threads=duckdb_threads,
            staging_chunk_bytes=_staging_chunk_bytes or staging_chunk_mb * 1024 * 1024,
            flatten_batch_bytes=_flatten_batch_bytes or flatten_batch_mb * 1024 * 1024,
            staging_format=staging_format,
            parser_backend=parser_backend,
            direct_parquet=direct_parquet,
        )
        if direct_parquet and keep_staging:
            raise ValueError("--direct-parquet requires --no-keep-staging")
    except (ValueError, KeyError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    if background and _job_id is None:
        _spawn_background_job(case_name, source, workers, keep_raw, keep_staging, case_root, options)
        return

    try:
        c = Case.open(case_name, case_root=case_root)
    except CaseNotFoundError:
        console.print(f"[yellow]case '{case_name}' not found, creating it[/yellow]")
        c = Case.create(case_name, case_root=case_root)

    if _job_id is not None:
        # This is the detached child spawned above: no live terminal to
        # draw a progress bar on, so progress is persisted straight to the
        # job status file instead (see ingest.jobs.write_job_status).
        _run_as_background_child(c, _job_id, case_name, source, workers, keep_raw, keep_staging, options)
    else:
        _run_in_foreground(c, source, workers, keep_raw, keep_staging, options)
