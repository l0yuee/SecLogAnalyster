from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseNotFoundError, NoSourcesFoundError
from ._render import console


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
    workers: int | None = typer.Option(None, "--workers", help="Parallel staging workers (default: CPU count)"),
    keep_raw: bool = typer.Option(
        False, "--keep-raw", help="Also capture raw EVTX record XML (slower, ~2x cost; .evtx sources only)"
    ),
    keep_staging: bool = typer.Option(
        True, "--keep-staging/--no-keep-staging", help="Keep staged NDJSON after flattening (cheap reprocessing)"
    ),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    try:
        c = Case.open(case_name, case_root=case_root)
    except CaseNotFoundError:
        console.print(f"[yellow]case '{case_name}' not found, creating it[/yellow]")
        c = Case.create(case_name, case_root=case_root)

    try:
        report = c.ingest(source, workers=workers, keep_raw=keep_raw, keep_staging=keep_staging)
    except NoSourcesFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    console.print(report.summary_text())
