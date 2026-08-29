from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, export_chunks_to_csv, print_df, print_df_chunks


def tasks_command(
    case_name: str = typer.Argument(...),
    suspicious: bool = typer.Option(False, "--suspicious", help="Only tasks flagged by the built-in heuristics"),
    out: Path | None = typer.Option(None, "--out", help="Write full results to CSV instead of printing a table"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    if "scheduled_tasks" not in c.db.tables:
        console.print("[yellow]no scheduled task definitions ingested for this case[/yellow]")
        raise typer.Exit(1)

    if suspicious:
        # The heuristic filter runs in pandas (see Case.suspicious_tasks),
        # not pushed-down SQL -- fine in practice, since a case's task
        # count is bounded by however many tasks exist on disk per host,
        # nowhere near web-log volumes.
        df = c.suspicious_tasks()
        if out:
            df.to_csv(out, index=False)
            console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
        else:
            print_df(df, title="Scheduled tasks")
        return

    chunks = c.scheduled_tasks_chunks()
    if out:
        n = export_chunks_to_csv(chunks, out)
        console.print(f"[green]wrote {n} rows to {out}[/green]")
    else:
        print_df_chunks(chunks, title="Scheduled tasks")
