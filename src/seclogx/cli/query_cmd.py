from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, export_chunks_to_csv, print_df, print_df_chunks


def query_command(
    case_name: str = typer.Argument(...),
    sql: str = typer.Argument(..., help="Raw SQL against any table in the case, e.g. events, web_logs (see `seclogx sources`)"),
    out: Path | None = typer.Option(None, "--out", help="Stream every matching row to CSV instead of printing a preview"),
    limit: int | None = typer.Option(None, "--limit"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    # Results are streamed in bounded-size chunks rather than fetched as one
    # DataFrame -- a query against events/web_logs/etc. can realistically
    # return far more than fits comfortably in memory (see query.py's
    # module docstring). Pushing --limit into the SQL itself (rather than
    # slicing an already-fetched DataFrame) means a limited query doesn't
    # pay to read more than it asked for.
    effective_sql = f"SELECT * FROM ({sql}) AS q LIMIT {int(limit)}" if limit else sql
    try:
        chunks = c.query_chunks(effective_sql)
        if out:
            n = export_chunks_to_csv(chunks, out)
            console.print(f"[green]wrote {n} rows to {out}[/green]")
        else:
            print_df_chunks(chunks)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


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
    """Row count per table (events, web_logs, web_error_logs, scheduled_tasks,
    exchange_message_tracking, exchange_logs, syslog, auditd_logs,
    journal_logs) currently in the case."""
    c = Case.open(case_name, case_root=case_root)
    print_df(c.table_counts(), title="Tables in case")


def table_command(
    case_name: str = typer.Argument(...),
    table_name: str = typer.Argument(..., help="Table name, e.g. web_logs, scheduled_tasks (see `seclogx sources`)"),
    out: Path | None = typer.Option(None, "--out", help="Stream every matching row to CSV instead of printing a preview"),
    limit: int | None = typer.Option(None, "--limit"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    """Full contents of any table this case has, as a DataFrame -- the
    same uniform access `events` gets via `summary`/`query`, generalized
    to every log family. Streamed in bounded-size chunks rather than
    fetched as one DataFrame -- a table can realistically be far larger
    than comfortably fits in memory (see query.py's module docstring)."""
    c = Case.open(case_name, case_root=case_root)
    if table_name not in c.db.tables:
        console.print(f"[yellow]case has no '{table_name}' table (see `seclogx sources`)[/yellow]")
        raise typer.Exit(1)
    sql = f"SELECT * FROM {table_name}" + (f" LIMIT {int(limit)}" if limit else "")
    chunks = c.query_chunks(sql)
    if out:
        n = export_chunks_to_csv(chunks, out)
        console.print(f"[green]wrote {n} rows to {out}[/green]")
    else:
        print_df_chunks(chunks, title=table_name)
