from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import typer
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseNotFoundError, NoSourcesFoundError
from ..ingest.common import now_iso
from ..ingest.jobs import job_log_path, jobs_dir, read_job_status, write_job_status
from ._render import console


def _spawn_background_job(
    case_name: str,
    source: list[str],
    workers: int | None,
    keep_raw: bool,
    keep_staging: bool,
    case_root: Path,
) -> None:
    job_id = str(uuid.uuid4())
    case_dir = Path(case_root) / case_name

    try:
        Case.open(case_name, case_root=case_root)
    except CaseNotFoundError:
        Case.create(case_name, case_root=case_root)

    jobs_dir(case_dir).mkdir(parents=True, exist_ok=True)
    log_path = job_log_path(case_dir, job_id)

    args = [sys.executable, "-m", "seclogx.cli.main", "ingest", case_name]
    for s in source:
        args += ["--source", s]
    if workers is not None:
        args += ["--workers", str(workers)]
    if keep_raw:
        args += ["--keep-raw"]
    args += ["--keep-staging" if keep_staging else "--no-keep-staging"]
    args += ["--case-root", str(case_root), "--_job-id", job_id]

    popen_kwargs: dict = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        # Detach from this process's session so the job survives the
        # parent (this CLI invocation, and the terminal it ran in) exiting.
        popen_kwargs["start_new_session"] = True

    with open(log_path, "wb") as log_file:
        subprocess.Popen(
            args, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **popen_kwargs
        )

    write_job_status(
        case_dir,
        job_id,
        {
            "job_id": job_id,
            "case_name": case_name,
            "sources": source,
            "phase": "scanning",
            "started_at": now_iso(),
            "updated_at": now_iso(),
        },
    )
    console.print(f"[green]Started background ingest job {job_id}[/green] for case '{case_name}'")
    console.print(f"  log: {log_path}")
    console.print(f"  check progress: seclogx ingest-status {case_name} {job_id}  (add --watch to follow it)")


def _run_as_background_child(c: Case, job_id: str, case_name: str, source, workers, keep_raw, keep_staging) -> None:
    # write_job_status() replaces the whole file rather than merging, so
    # fields the parent wrote before spawning us (started_at, sources) --
    # which ProgressReporter's snapshot doesn't know about -- have to be
    # carried forward into every write here, or the first progress update
    # would silently erase them.
    existing = read_job_status(c.case_dir, job_id) or {}
    started_at = existing.get("started_at") or now_iso()

    def on_progress(snapshot: dict) -> None:
        snapshot["job_id"] = job_id
        snapshot["case_name"] = case_name
        snapshot["sources"] = source
        snapshot["started_at"] = started_at
        snapshot["updated_at"] = now_iso()
        write_job_status(c.case_dir, job_id, snapshot)

    try:
        report = c.ingest(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging, on_progress=on_progress)
    except NoSourcesFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    except Exception as e:  # noqa: BLE001 -- nothing else is watching this process live; record the failure
        write_job_status(
            c.case_dir,
            job_id,
            {
                "job_id": job_id,
                "case_name": case_name,
                "sources": source,
                "started_at": started_at,
                "phase": "failed",
                "error": str(e),
                "updated_at": now_iso(),
            },
        )
        raise

    console.print(report.summary_text())


def _run_in_foreground(c: Case, source, workers, keep_raw, keep_staging) -> None:
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
                detail = f"scanned {snapshot.get('files_scanned', 0)} files"
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
            report = c.ingest(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging, on_progress=on_progress)
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
            "Source path to scan for .evtx, Scheduled Task definitions, IIS/nginx/Apache/Tomcat "
            "access logs, and Exchange CSV logs, optionally PATH:HOST. Repeatable."
        ),
    ),
    workers: int | None = typer.Option(None, "--workers", help="Parallel staging workers (default: up to 8)"),
    keep_raw: bool = typer.Option(
        False, "--keep-raw", help="Also capture raw EVTX record XML (slower, ~2x cost; .evtx sources only)"
    ),
    keep_staging: bool = typer.Option(
        True, "--keep-staging/--no-keep-staging", help="Keep staged NDJSON after flattening (cheap reprocessing)"
    ),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
    background: bool = typer.Option(
        False,
        "--background",
        "-b",
        help="Run the import detached in the background and return immediately; "
        "check progress with `seclogx ingest-status`",
    ),
    _job_id: str = typer.Option(None, "--_job-id", hidden=True),
) -> None:
    if background and _job_id is None:
        _spawn_background_job(case_name, source, workers, keep_raw, keep_staging, case_root)
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
        _run_as_background_child(c, _job_id, case_name, source, workers, keep_raw, keep_staging)
    else:
        _run_in_foreground(c, source, workers, keep_raw, keep_staging)
