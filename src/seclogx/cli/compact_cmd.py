from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console


def compact_command(
    case_name: str = typer.Argument(...),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    """Merge small local Parquet files while preserving existing readers."""
    case = Case.open(case_name, case_root=case_root)
    console.print(case.compact().summary_text())
