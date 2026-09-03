from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, export_chunks_to_csv, print_df, print_df_chunks


def registry_command(
    case_name: str = typer.Argument(...),
    suspicious: bool = typer.Option(False, "--suspicious", help="Only entries flagged by the built-in heuristics"),
    hive_type: str | None = typer.Option(
        None, "--hive-type", help="Filter to one hive type (system/software/sam/security/default/ntuser/usrclass/amcache/bcd)"
    ),
    out: Path | None = typer.Option(None, "--out", help="Write full results to CSV instead of printing a table"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    if "registry" not in c.db.tables:
        console.print("[yellow]no registry hives ingested for this case[/yellow]")
        raise typer.Exit(1)

    if suspicious:
        # The heuristic filter narrows down with SQL first (see
        # Case.suspicious_registry) -- the result is already small, so
        # this is fine to fetch eagerly like Case.suspicious_tasks().
        df = c.suspicious_registry()
        if out:
            df.to_csv(out, index=False)
            console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
        else:
            print_df(df, title="Suspicious registry entries")
        return

    chunks = c.registry_chunks(hive_type=hive_type)
    if out:
        n = export_chunks_to_csv(chunks, out)
        console.print(f"[green]wrote {n} rows to {out}[/green]")
    else:
        print_df_chunks(chunks, title="Registry")
