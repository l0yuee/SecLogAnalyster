from __future__ import annotations

import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()


def print_df(df: pd.DataFrame, title: str | None = None, max_rows: int = 50) -> None:
    if df.empty:
        console.print("[yellow]no rows[/yellow]")
        return
    table = Table(title=title, show_lines=False)
    for col in df.columns:
        table.add_column(str(col))
    for _, row in df.head(max_rows).iterrows():
        table.add_row(*[str(v) for v in row])
    console.print(table)
    if len(df) > max_rows:
        console.print(f"[dim]... {len(df) - max_rows} more rows (use --out to export all)[/dim]")
