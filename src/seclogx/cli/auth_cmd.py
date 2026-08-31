from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, print_df


def auth_command(
    case_name: str = typer.Argument(...),
    out: Path | None = typer.Option(None, "--out", help="Write full results to CSV instead of printing a table"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    if "syslog" not in c.db.tables:
        console.print("[yellow]no syslog data ingested for this case[/yellow]")
        raise typer.Exit(1)

    # The heuristic filter runs in pandas (see Case.auth_events), not
    # pushed-down SQL -- same tradeoff as Case.suspicious_tasks().
    df = c.auth_events()
    if out:
        df.to_csv(out, index=False)
        console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
    else:
        print_df(df, title="Auth events (SSH / sudo / PAM / account management)")
