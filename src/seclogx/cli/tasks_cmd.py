from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, print_df


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

    df = c.suspicious_tasks() if suspicious else c.query("SELECT * FROM scheduled_tasks ORDER BY task_path")
    if out:
        df.to_csv(out, index=False)
        console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
    else:
        print_df(df, title="Scheduled tasks")
