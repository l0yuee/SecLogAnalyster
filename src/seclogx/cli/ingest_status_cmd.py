from __future__ import annotations

import time
from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseNotFoundError
from ..ingest.jobs import list_jobs, read_job_status
from ._render import console

_TERMINAL_PHASES = ("done", "failed")


def _print_status(status: dict) -> None:
    console.print(f"[bold]job {status.get('job_id')}[/bold]  phase={status.get('phase')}")
    console.print(
        f"  scanned {status.get('files_scanned', 0)}  "
        f"discovered evtx={status.get('evtx_discovered', 0)} aux={status.get('aux_discovered', 0)}"
    )
    console.print(
        f"  staged   ok={status.get('files_ok', 0)} partial={status.get('files_partial', 0)} "
        f"failed={status.get('files_failed', 0)} unsupported={status.get('files_unknown', 0)}"
    )
    rows = status.get("rows_written") or {}
    if rows:
        console.print("  rows written per table:")
        for table, count in sorted(rows.items()):
            console.print(f"    {table}: {count}")
    if status.get("error"):
        console.print(f"  [red]error: {status['error']}[/red]")
    console.print(f"  started_at: {status.get('started_at')}   updated_at: {status.get('updated_at')}")


def ingest_status_command(
    case_name: str = typer.Argument(..., help="Case name"),
    job_id: str = typer.Argument(None, help="Job id to check; omit for the most recently started job"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
    watch: bool = typer.Option(False, "--watch", help="Poll every second until the job finishes"),
) -> None:
    try:
        c = Case.open(case_name, case_root=case_root)
    except CaseNotFoundError:
        console.print(f"[red]case '{case_name}' not found[/red]")
        raise typer.Exit(1)

    if job_id:
        status = read_job_status(c.case_dir, job_id)
        if status is None:
            console.print(f"[red]no ingest job '{job_id}' found for case '{case_name}'[/red]")
            raise typer.Exit(1)
    else:
        jobs = list_jobs(c.case_dir)
        if not jobs:
            console.print(f"[yellow]no background ingest jobs recorded for case '{case_name}'[/yellow]")
            raise typer.Exit(1)
        status = jobs[0]
        job_id = status.get("job_id")

    _print_status(status)

    if watch:
        last = status
        while last.get("phase") not in _TERMINAL_PHASES:
            time.sleep(1.0)
            latest = read_job_status(c.case_dir, job_id)
            if latest is None:
                break
            if latest != last:
                console.print("")
                _print_status(latest)
            last = latest
