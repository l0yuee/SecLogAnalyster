"""Cancel local ingest jobs and reclaim inactive uncommitted output."""
from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseNotFoundError
from ._render import console


def ingest_cancel_command(
    case_name: str = typer.Argument(...),
    job_id: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    """Stop an owned background ingest process and its local workers."""
    try:
        status = Case.open(case_name, case_root=case_root).cancel_job(job_id)
    except (CaseNotFoundError, KeyError, ValueError, RuntimeError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"job {job_id}  phase={status.get('phase')}")


def ingest_cleanup_command(
    case_name: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
    log_retention_days: int = typer.Option(7, "--log-retention-days", min=0),
) -> None:
    """Reclaim inactive uncommitted data and expired logs; keep evidence and audit JSON."""
    try:
        result = Case.open(case_name, case_root=case_root).cleanup_ingest(log_retention_days=log_retention_days)
    except (CaseNotFoundError, ValueError, RuntimeError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"Removed {len(result['uncommitted_paths'])} uncommitted paths, "
                  f"{len(result['retired_paths'])} retired data files and {len(result['log_paths'])} job logs")
