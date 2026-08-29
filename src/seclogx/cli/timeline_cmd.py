from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, export_chunks_to_csv, print_df_chunks


def timeline_command(
    case_name: str = typer.Argument(...),
    start: str | None = typer.Option(None, "--start", help="ISO timestamp lower bound"),
    end: str | None = typer.Option(None, "--end", help="ISO timestamp upper bound"),
    host: str | None = typer.Option(None, "--host"),
    channel: str | None = typer.Option(None, "--channel"),
    event_id: list[int] = typer.Option(None, "--event-id", help="Repeatable"),
    out: Path | None = typer.Option(None, "--out", help="Write full timeline to CSV"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    # Streamed in bounded-size chunks rather than fetched as one DataFrame --
    # an unfiltered or lightly-filtered timeline over a large case can
    # still be far bigger than comfortably fits in memory.
    c = Case.open(case_name, case_root=case_root)
    if "events" not in c.db.tables:
        console.print("[yellow]case has no ingested Windows Event Log data[/yellow]")
        raise typer.Exit(1)
    chunks = c.timeline_chunks(
        start=start,
        end=end,
        host=host,
        channel=channel,
        event_id=list(event_id) if event_id else None,
    )
    if out:
        n = export_chunks_to_csv(chunks, out)
        console.print(f"[green]wrote {n} rows to {out}[/green]")
    else:
        print_df_chunks(chunks, title="Timeline", max_rows=100)
