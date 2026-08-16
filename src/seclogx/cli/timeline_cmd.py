from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ._render import console, print_df


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
    c = Case.open(case_name, case_root=case_root)
    df = c.timeline(
        start=start,
        end=end,
        host=host,
        channel=channel,
        event_id=list(event_id) if event_id else None,
    )
    if out:
        df.to_csv(out, index=False)
        console.print(f"[green]wrote {len(df)} rows to {out}[/green]")
    else:
        print_df(df, title="Timeline", max_rows=100)
