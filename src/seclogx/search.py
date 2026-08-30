"""A structured, non-SQL query interface: conditions expressed as plain
field/operator/value data, translated to safely-parameterized DuckDB SQL
-- built for analysts who don't want to write SQL by hand. Supports exact
matching, fuzzy (substring) matching, and regular expressions, each
optionally case-insensitive, with multiple conditions combined by AND or
OR, against any table in the case.

Field resolution needs no per-table hardcoding of its own: a name that
matches one of the table's real columns is used directly; otherwise it's
looked up as a key inside whichever of the table's columns hold a JSON
*object* (`event_data`, `extra`, `fields`, depending on the table). Which
columns those are is read from this project's own schema modules
(`schema.py`'s `CORE_COLUMNS`, `logsources/schema.py`'s `TABLES`) -- the
same declared-JSON-type annotations the Sigma pipeline already treats as
the source of truth -- rather than DuckDB's own catalog: every
JSON-bearing column here is physically stored as VARCHAR, not DuckDB's
JSON type (a deliberate earlier fix, see schema.py, to keep Parquet's
inferred physical type stable across ingest batches where such a column
can be all-NULL), so content-sniffing the catalog for "is this actually
JSON" is exactly the kind of thing that breaks silently on an all-NULL
column in a particular case -- reading the declared type avoids that.
JSON *array* columns (`scheduled_tasks.actions`/`triggers`) are excluded
even though they're declared JSON too -- keyed extraction doesn't apply
to a list the same way; search those directly as whole-column text
instead. A table this project's schema modules don't know about (a
hypothetical future one added without updating this file) falls back to
sniffing its columns' actual content, so nothing breaks outright -- it
just doesn't get this project's exact object/array distinction for free.

Every eager result goes through the same memory-safety check as the rest
of the project (see query.py's `ResultSizeEstimate`): `search()` refuses
to materialize a result judged too large for the analyst's available
memory, and points at `search_chunks()` (bounded-memory iteration) or
`search_to_csv()` (streamed export) instead of just trying and risking an
out-of-memory crash.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal

import pandas as pd

from .csvutil import export_chunks_to_csv
from .errors import ResultTooLargeError, UnknownFieldError
from .ingest.logsources.schema import TABLES as _LOGSOURCE_TABLES
from .query import DEFAULT_CHUNKSIZE, CaseDB
from .schema import CORE_COLUMNS as _EVENTS_CORE_COLUMNS

# Declared JSON *array* columns (as opposed to JSON *object* columns) --
# keyed extraction (`->> 'field'`) doesn't apply to a list the same way,
# so these are excluded from JSON-object field resolution even though
# they're declared JSON in logsources/schema.py.
_JSON_ARRAY_COLUMNS = {"actions", "triggers"}

Op = Literal["equals", "contains", "regex"]
Match = Literal["all", "any"]


@dataclass
class Condition:
    """One filter: `field` <op> one of `values` (multiple values combine
    with OR within this single condition -- e.g. status equals 404 or
    500). `case_sensitive` defaults to False, since that's what most
    analysts expect from a fuzzy/plain-language search."""

    field: str
    op: Op
    values: list[str]
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        if self.op not in ("equals", "contains", "regex"):
            raise ValueError(f"unknown operator {self.op!r} -- must be 'equals', 'contains', or 'regex'")
        if not self.values:
            raise ValueError(f"condition on field {self.field!r} needs at least one value")


def conditions_from_dicts(
    eq: dict[str, str | list[str]] | None = None,
    contains: dict[str, str | list[str]] | None = None,
    regex: dict[str, str | list[str]] | None = None,
    case_sensitive: bool = False,
) -> list[Condition]:
    """Build a condition list from the friendly `{field: value_or_values}`
    dicts `Case.search()`/etc. accept -- the ergonomic entry point for
    notebook use, so most callers never construct `Condition` by hand."""
    conditions: list[Condition] = []
    for op, mapping in (("equals", eq), ("contains", contains), ("regex", regex)):
        for field_name, value in (mapping or {}).items():
            values = value if isinstance(value, list) else [value]
            conditions.append(Condition(field=field_name, op=op, values=[str(v) for v in values], case_sensitive=case_sensitive))
    return conditions


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _table_columns(db: CaseDB, table: str) -> list[tuple[str, str]]:
    return [(row[0], row[1]) for row in db.connection.execute(f"DESCRIBE {_quote_ident(table)}").fetchall()]


def _declared_json_object_columns(table: str) -> list[str] | None:
    """JSON-object columns per this project's own schema modules -- the
    source of truth, when `table` is one they know about. Returns None for
    an unrecognized table so the caller can fall back to content-sniffing
    instead of asserting there's nothing to find."""
    if table == "events":
        declared = [name for name, dtype, _ in _EVENTS_CORE_COLUMNS if dtype == "JSON"]
    elif table in _LOGSOURCE_TABLES:
        declared = [name for name, dtype in _LOGSOURCE_TABLES[table]["columns"] if dtype == "JSON"]
    else:
        return None
    return [c for c in declared if c not in _JSON_ARRAY_COLUMNS]


def _sniff_json_object_columns(db: CaseDB, table: str) -> list[str]:
    """Fallback for a table this project's schema modules don't recognize:
    sample one non-NULL value per VARCHAR column and check it looks like
    `{...}`. Unlike the declared-type path, this can miss a JSON-object
    column that happens to be all-NULL in this particular case -- exactly
    why the declared path is preferred whenever it's available."""
    candidates = [name for name, dtype in _table_columns(db, table) if dtype == "VARCHAR"]
    found = []
    for col in candidates:
        row = db.connection.execute(
            f"SELECT {_quote_ident(col)} FROM {_quote_ident(table)} WHERE {_quote_ident(col)} IS NOT NULL LIMIT 1"
        ).fetchone()
        if row and isinstance(row[0], str) and row[0].lstrip().startswith("{"):
            found.append(col)
    return found


def _json_object_columns(db: CaseDB, table: str) -> list[str]:
    """Which of `table`'s columns actually hold a JSON object -- see the
    module docstring. Cached on the CaseDB instance since field
    resolution calls this once per condition."""
    cached = db._json_object_columns_cache.get(table)
    if cached is not None:
        return cached

    found = _declared_json_object_columns(table)
    if found is None:
        found = _sniff_json_object_columns(db, table)

    db._json_object_columns_cache[table] = found
    return found


def resolve_field(db: CaseDB, table: str, field_name: str) -> str:
    """Turn a plain field name into a SQL expression against `table`: the
    column itself if it matches one (case-insensitively, forgiving of
    typos like `Status` vs `status`), otherwise a JSON-key extraction from
    whichever JSON-object column(s) the table has. Raises
    UnknownFieldError (listing what's actually available) if neither
    resolves -- the non-SQL-analyst-friendly alternative to a cryptic
    "column not found" from the database itself."""
    columns = _table_columns(db, table)
    by_lower = {name.lower(): name for name, _ in columns}
    if field_name.lower() in by_lower:
        return _quote_ident(by_lower[field_name.lower()])

    json_columns = _json_object_columns(db, table)
    if not json_columns:
        available = ", ".join(name for name, _ in columns)
        raise UnknownFieldError(
            f"'{field_name}' is not a column of '{table}', and this table has no JSON field to search inside "
            f"either. Available columns: {available}"
        )
    escaped = field_name.replace("'", "''")
    if len(json_columns) == 1:
        return f"({_quote_ident(json_columns[0])} ->> '{escaped}')"
    return "COALESCE(" + ", ".join(f"({_quote_ident(c)} ->> '{escaped}')" for c in json_columns) + ")"


DEFAULT_FIELD_SAMPLE_SIZE = 5000


def discover_fields(db: CaseDB, table: str, sample_size: int = DEFAULT_FIELD_SAMPLE_SIZE) -> pd.DataFrame:
    """What can I actually search on? Answers it from this case's real
    ingested data rather than static documentation -- a `web_logs` field
    list looks different depending on what a site's IIS admin chose to
    log, and `event_data`'s keys are entirely provider-specific, so no
    fixed list would be accurate for every case anyway.

    Returns one row per field: `field` (the name to pass to
    eq=/contains=/regex=), `where` ('column' for a real table column, or
    'inside <json column>' for a key found inside a JSON catchall),
    `seen_in_sample` (how many of the sampled rows had a non-NULL/present
    value for it -- a rough popularity signal, not exact), and `example`
    (one real, truncated value, so you can see the shape of the data
    before writing a condition against it).

    Sampled (`LIMIT sample_size`, one query), not an exhaustive scan --
    memory- and time-bounded regardless of the table's total size, at the
    cost of a rare field present in fewer than 1-in-`sample_size` rows
    potentially not showing up. Rows are ordered most-common-first within
    'column' fields and within JSON-catchall fields separately, columns
    listed before catchall keys, since a real column is always a safe,
    fast condition while a catchall key search has to fall back to a
    slower per-row JSON extraction (see `resolve_field`)."""
    if table not in db.tables:
        raise ValueError(f"case has no '{table}' table (see `seclogx sources` / Case.table_counts())")

    json_columns = set(_json_object_columns(db, table))
    sample = db.connection.execute(f"SELECT * FROM {_quote_ident(table)} LIMIT {int(sample_size)}").fetchdf()

    rows: list[dict] = []
    for col in sample.columns:
        non_null = sample[col].notna()
        if col in json_columns:
            key_counts: Counter = Counter()
            key_examples: dict[str, str] = {}
            for raw in sample.loc[non_null, col]:
                try:
                    obj = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue
                for key, value in obj.items():
                    if value in (None, ""):
                        continue
                    key_counts[key] += 1
                    key_examples.setdefault(key, str(value))
            for key, count in key_counts.items():
                rows.append(
                    {
                        "field": key,
                        "where": f"inside {col}",
                        "seen_in_sample": count,
                        "example": key_examples[key][:80],
                    }
                )
        else:
            count = int(non_null.sum())
            example = sample.loc[non_null, col].iloc[0] if count else None
            rows.append(
                {
                    "field": col,
                    "where": "column",
                    "seen_in_sample": count,
                    "example": None if example is None else str(example)[:80],
                }
            )

    result = pd.DataFrame(rows, columns=["field", "where", "seen_in_sample", "example"])
    if result.empty:
        return result
    is_column = (result["where"] == "column").astype(int)
    return (
        result.assign(_is_column=is_column)
        .sort_values(["_is_column", "seen_in_sample"], ascending=[False, False])
        .drop(columns="_is_column")
        .reset_index(drop=True)
    )


def _escape_like_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _condition_sql(db: CaseDB, table: str, condition: Condition) -> tuple[str, list]:
    expr = resolve_field(db, table, condition.field)
    fragments: list[str] = []
    params: list = []

    if condition.op == "equals":
        for v in condition.values:
            if condition.case_sensitive:
                fragments.append(f"CAST({expr} AS VARCHAR) = ?")
                params.append(v)
            else:
                fragments.append(f"LOWER(CAST({expr} AS VARCHAR)) = LOWER(?)")
                params.append(v)
    elif condition.op == "contains":
        like_op = "LIKE" if condition.case_sensitive else "ILIKE"
        for v in condition.values:
            fragments.append(f"CAST({expr} AS VARCHAR) {like_op} ? ESCAPE '\\'")
            params.append(f"%{_escape_like_literal(v)}%")
    else:  # regex
        options = "" if condition.case_sensitive else "i"
        for v in condition.values:
            fragments.append("regexp_matches(CAST(" + expr + " AS VARCHAR), ?, ?)")
            params.extend([v, options])

    return "(" + " OR ".join(fragments) + ")", params


def build_search_sql(db: CaseDB, table: str, conditions: list[Condition], match: Match = "all") -> tuple[str, list]:
    """The SQL + parameters a set of conditions compiles to -- exposed
    directly for anyone who wants to see or reuse the generated query
    (e.g. as a starting point for hand-written SQL)."""
    if table not in db.tables:
        raise ValueError(f"case has no '{table}' table (see `seclogx sources` / Case.table_counts())")
    if match not in ("all", "any"):
        raise ValueError(f"match must be 'all' or 'any', got {match!r}")

    if not conditions:
        return f"SELECT * FROM {_quote_ident(table)}", []

    joiner = " AND " if match == "all" else " OR "
    parts: list[str] = []
    params: list = []
    for condition in conditions:
        sql, p = _condition_sql(db, table, condition)
        parts.append(sql)
        params.extend(p)
    return f"SELECT * FROM {_quote_ident(table)} WHERE " + joiner.join(parts), params


def search(
    db: CaseDB, table: str, conditions: list[Condition], match: Match = "all", safety_fraction: float = 0.25
) -> pd.DataFrame:
    """Eager, whole-result-as-one-DataFrame search -- refuses (raising
    ResultTooLargeError) rather than risking an out-of-memory crash if the
    estimated result is too large for the analyst's available memory. Use
    `search_chunks()`/`search_to_csv()` for a result that's expected to be
    large."""
    sql, params = build_search_sql(db, table, conditions, match)
    estimate = db.estimate(sql, params)
    if not estimate.fits_in_memory(safety_fraction):
        raise ResultTooLargeError(
            f"this search matches an estimated {estimate.row_count:,} rows (~{estimate.estimated_bytes / 1e6:.0f} MB) "
            "-- too large to safely hold in memory as one DataFrame. Use search_chunks() to iterate it in "
            "bounded-size pieces instead, or search_to_csv() to stream every matching row straight to a file."
        )
    return db.sql(sql, params)


def search_chunks(
    db: CaseDB, table: str, conditions: list[Condition], match: Match = "all", chunksize: int = DEFAULT_CHUNKSIZE
) -> Iterator[pd.DataFrame]:
    """Bounded-memory alternative to `search()` -- an Iterator[pd.DataFrame]
    instead of one DataFrame, safe at any result size regardless of the
    analyst's available memory."""
    sql, params = build_search_sql(db, table, conditions, match)
    return db.sql_chunks(sql, params, chunksize=chunksize)


def search_to_csv(
    db: CaseDB,
    table: str,
    conditions: list[Condition],
    path: str | Path,
    match: Match = "all",
    chunksize: int = DEFAULT_CHUNKSIZE,
) -> int:
    """Stream every matching row straight to a CSV file -- the other
    bounded-memory alternative to `search()`, for when the analyst wants
    the full result on disk rather than iterated in Python. Returns the
    row count written."""
    return export_chunks_to_csv(search_chunks(db, table, conditions, match=match, chunksize=chunksize), Path(path))
