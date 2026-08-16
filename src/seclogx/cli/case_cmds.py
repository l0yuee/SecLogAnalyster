from __future__ import annotations

import json
from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import CaseAlreadyExistsError, CaseNotFoundError
from ._render import console

case_app = typer.Typer(help="Manage case workspaces")


@case_app.command("init")
def init(
    name: str,
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--dir"),
) -> None:
    try:
        c = Case.create(name, case_root=case_root)
    except CaseAlreadyExistsError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]created case '{name}' at {c.case_dir}[/green]")


@case_app.command("list")
def list_cases(case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--dir")) -> None:
    names = Case.list_cases(case_root=case_root)
    if not names:
        console.print("[yellow]no cases found[/yellow]")
        return
    for n in names:
        console.print(n)


@case_app.command("info")
def info(
    name: str,
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--dir"),
) -> None:
    try:
        c = Case.open(name, case_root=case_root)
    except CaseNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print_json(json.dumps(c.info(), indent=2))
