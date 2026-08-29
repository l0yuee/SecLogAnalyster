from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

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


def print_df_chunks(chunks: Iterable[pd.DataFrame], title: str | None = None, max_rows: int = 50) -> None:
    """Console preview built from a chunked result -- pulls only enough
    rows for the table, never the full result, so previewing a query
    against a table too large to fit in memory (real-world web access/error
    log volumes especially) doesn't itself require pulling that much data.
    Unlike `print_df`, the "more rows" note can't report an exact count
    (that would require materializing everything to know it) -- it just
    says more exist."""
    collected: list[pd.DataFrame] = []
    total = 0
    more = False
    for chunk in chunks:
        collected.append(chunk)
        total += len(chunk)
        if total > max_rows:
            more = True
            break
    if not collected:
        console.print("[yellow]no rows[/yellow]")
        return
    df = pd.concat(collected, ignore_index=True).head(max_rows)
    table = Table(title=title, show_lines=False)
    for col in df.columns:
        table.add_column(str(col))
    for _, row in df.iterrows():
        table.add_row(*[str(v) for v in row])
    console.print(table)
    if more:
        console.print("[dim]... more rows not shown (use --out to export all)[/dim]")


def export_chunks_to_csv(chunks: Iterator[pd.DataFrame], path: Path) -> int:
    """Stream a chunked result straight to CSV, one chunk at a time --
    never holding more than one chunk in memory, so `--out` on a
    real-world-sized table doesn't require the whole thing to fit in RAM
    first (see query.py's module docstring). Returns the total row count
    written."""
    total = 0
    header_written = False
    with open(path, "w", newline="") as f:
        for chunk in chunks:
            chunk.to_csv(f, index=False, header=not header_written)
            header_written = True
            total += len(chunk)
    if not header_written:
        open(path, "w").close()
    return total
