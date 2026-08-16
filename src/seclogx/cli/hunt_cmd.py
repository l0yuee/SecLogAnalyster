from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console


def hunt_command(
    case_name: str = typer.Argument(...),
    rules: Path | None = typer.Option(None, "--rules", help="Sigma rules directory (default: bundled starter set)"),
    min_level: str | None = typer.Option(None, "--min-level", help="informational|low|medium|high|critical"),
    out: Path | None = typer.Option(None, "--out", help="Write matches to CSV"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    c = Case.open(case_name, case_root=case_root)
    results = c.hunt(rules_dir=rules, min_level=min_level)
    console.print(results.summary_text())
    if out:
        results.save(out)
        console.print(f"[green]wrote {len(results.matches)} matched rows to {out}[/green]")
