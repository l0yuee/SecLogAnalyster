"""`seclogx search` -- query any table without writing SQL: exact,
fuzzy/substring, and regular-expression conditions expressed as plain
FIELD=VALUE flags, combined with AND/OR. See src/seclogx/search.py for the
underlying condition-to-SQL translation shared with the Python API."""

from __future__ import annotations

from pathlib import Path

import typer

from ..case import Case
from ..config import DEFAULT_CASE_ROOT
from ..errors import UnknownFieldError
from ..search import Condition, build_search_sql
from ._render import console, export_chunks_to_csv, print_df_chunks


def _parse_field_value(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise typer.BadParameter(f"expected FIELD=VALUE, got {raw!r}")
    field, _, value = raw.partition("=")
    field = field.strip()
    if not field:
        raise typer.BadParameter(f"expected FIELD=VALUE, got {raw!r}")
    return field, value


def search_command(
    case_name: str = typer.Argument(...),
    table_name: str = typer.Argument(..., help="Table to search, e.g. web_logs, events (see `seclogx sources`)"),
    eq: list[str] = typer.Option(
        [], "--eq", help="Exact match: FIELD=VALUE. Comma-separate multiple values for OR (e.g. status=404,500). Repeatable."
    ),
    contains: list[str] = typer.Option(
        [], "--contains", help="Fuzzy/substring match: FIELD=VALUE. Comma-separate for OR. Repeatable."
    ),
    regex: list[str] = typer.Option(
        [], "--regex", help="Regular-expression match: FIELD=PATTERN (not comma-split). Repeatable."
    ),
    match_any: bool = typer.Option(False, "--match-any", help="Combine conditions with OR instead of the default AND"),
    case_sensitive: bool = typer.Option(
        False, "--case-sensitive", help="Case-sensitive matching (default: case-insensitive)"
    ),
    out: Path | None = typer.Option(None, "--out", help="Stream every matching row to CSV instead of a preview"),
    limit: int | None = typer.Option(None, "--limit"),
    case_root: Path = typer.Option(DEFAULT_CASE_ROOT, "--case-root"),
) -> None:
    """Query any table without writing SQL.

    \b
    seclogx search incident42 web_logs --contains uri_stem=admin --eq status=401,403
    seclogx search incident42 events --regex CommandLine=".*-enc.*" --eq channel="Microsoft-Windows-Sysmon/Operational"
    seclogx search incident42 scheduled_tasks --eq hidden=true --match-any --contains actions=powershell
    """
    c = Case.open(case_name, case_root=case_root)
    if table_name not in c.db.tables:
        console.print(f"[yellow]case has no '{table_name}' table (see `seclogx sources`)[/yellow]")
        raise typer.Exit(1)

    conditions: list[Condition] = []
    for raw in eq:
        field, value = _parse_field_value(raw)
        conditions.append(Condition(field=field, op="equals", values=[v.strip() for v in value.split(",")], case_sensitive=case_sensitive))
    for raw in contains:
        field, value = _parse_field_value(raw)
        conditions.append(
            Condition(field=field, op="contains", values=[v.strip() for v in value.split(",")], case_sensitive=case_sensitive)
        )
    for raw in regex:
        field, value = _parse_field_value(raw)
        conditions.append(Condition(field=field, op="regex", values=[value], case_sensitive=case_sensitive))

    try:
        sql, params = build_search_sql(c.db, table_name, conditions, match="any" if match_any else "all")
    except (ValueError, UnknownFieldError) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    if limit:
        sql = f"SELECT * FROM ({sql}) AS _limited LIMIT {int(limit)}"

    try:
        estimate = c.db.estimate(sql, params)
    except Exception as e:  # noqa: BLE001 -- e.g. an invalid regex pattern; surface clearly, not a raw traceback
        console.print(f"[red]search failed: {e}[/red]")
        raise typer.Exit(1)

    if estimate.row_count == 0:
        console.print("[yellow]no rows matched[/yellow]")
        return

    size_note = f"{estimate.row_count:,} rows matched (~{estimate.estimated_bytes / 1e6:.0f} MB estimated)"
    chunks = c.db.sql_chunks(sql, params)

    if out:
        console.print(size_note)
        n = export_chunks_to_csv(chunks, out)
        console.print(f"[green]wrote {n} rows to {out}[/green]")
    else:
        if not estimate.fits_in_memory():
            console.print(
                f"[yellow]{size_note} -- too large to comfortably hold in memory as one result; "
                "showing a preview only. Use --out to stream every matching row to a CSV file instead.[/yellow]"
            )
        else:
            console.print(f"[dim]{size_note}[/dim]")
        print_df_chunks(chunks, title=table_name)
