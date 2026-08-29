from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, print_df


def query_command(
    case_name: str = typer.Argument(...),
    sql: str = typer.Argument(..., help="Raw SQL against the case's `events` view"),
    out: Path | None = typer.Option(None, "--out", help="Write full results to CSV instead of printing a table"),
    limit: int | None = typer.Option(None, "--limit"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    try:
        df = c.query(sql)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    if limit:
        df = df.head(limit)
    if out:
        df.to_csv(out, index=False)
        console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
    else:
        print_df(df)


def summary_command(
    case_name: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    print_df(c.summary(), title="Event summary", max_rows=100)


def channels_command(
    case_name: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    for ch in c.channels():
        console.print(ch)


def sources_command(
    case_name: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    """Row count per table (events, web_logs, scheduled_tasks,
    exchange_message_tracking, exchange_logs) currently in the case."""
    c = Case.open(case_name, case_root=case_root)
    print_df(c.table_counts(), title="Tables in case")
