"""Cross-host supertimeline: a single time-sorted view over a case's events,
filterable the way an analyst actually narrows down an investigation."""

from __future__ import annotations

from typing import Iterator

import pandas as pd

from .query import DEFAULT_CHUNKSIZE, CaseDB

_SELECT = (
    "SELECT time_created, host, computer, channel, event_id, provider_name, "
    "process_id, user_sid, event_data, source_file FROM events"
)


def _timeline_where(
    start=None, end=None, host: str | None = None, channel: str | None = None, event_id: int | list[int] | None = None
) -> tuple[str, list]:
    conds, params = [], []
    if start is not None:
        conds.append("time_created >= ?")
        params.append(start)
    if end is not None:
        conds.append("time_created <= ?")
        params.append(end)
    if host is not None:
        conds.append("host = ?")
        params.append(host)
    if channel is not None:
        conds.append("channel = ?")
        params.append(channel)
    if event_id is not None:
        ids = event_id if isinstance(event_id, (list, tuple)) else [event_id]
        conds.append(f"event_id IN ({','.join('?' for _ in ids)})")
        params.extend(ids)
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    return where, params


def build_timeline(
    db: CaseDB,
    start=None,
    end=None,
    host: str | None = None,
    channel: str | None = None,
    event_id: int | list[int] | None = None,
) -> pd.DataFrame:
    where, params = _timeline_where(start, end, host, channel, event_id)
    return db.sql(f"{_SELECT} {where} ORDER BY time_created", params)


def build_timeline_chunks(
    db: CaseDB,
    start=None,
    end=None,
    host: str | None = None,
    channel: str | None = None,
    event_id: int | list[int] | None = None,
    chunksize: int = DEFAULT_CHUNKSIZE,
) -> Iterator[pd.DataFrame]:
    """Bounded-memory alternative to `build_timeline()` -- an unfiltered or
    lightly-filtered timeline over a large case can still be far bigger
    than comfortably fits in one DataFrame; see query.py's module
    docstring for why this matters at real-world log volumes."""
    where, params = _timeline_where(start, end, host, channel, event_id)
    return db.sql_chunks(f"{_SELECT} {where} ORDER BY time_created", params, chunksize=chunksize)
