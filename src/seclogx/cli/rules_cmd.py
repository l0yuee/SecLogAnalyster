from __future__ import annotations

from pathlib import Path

import typer

from ..config import BUNDLED_SIGMA_RULES_DIR
from ..detect.backend import DuckDBBackend
from ..detect.pipeline import seclogx_pipeline
from ..detect.rules import load_rules
from ._render import console

rules_app = typer.Typer(help="Inspect Sigma rule loading/conversion")


@rules_app.command("validate")
def validate(
    rules: Path = typer.Option(BUNDLED_SIGMA_RULES_DIR, "--rules", help="Sigma rules directory"),
) -> None:
    load_result = load_rules(rules)
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())

    ok, failed = 0, 0
    for rule in load_result.rules:
        try:
            backend.convert_rule(rule)
            ok += 1
        except Exception as e:
            failed += 1
            console.print(f"[red]FAIL[/red] {rule.title} -- {e}")

    console.print(f"\n[green]{ok} rules convert successfully[/green], [red]{failed} failed conversion[/red]")
    if load_result.skipped:
        console.print(f"[yellow]{len(load_result.skipped)} rules skipped at load time:[/yellow]")
        for path, reason in load_result.skipped:
            console.print(f"  {path}: {reason}")
