"""Cross-host supertimeline: a single time-sorted view over a case's events,
filterable the way an analyst actually narrows down an investigation."""

from __future__ import annotations

import pandas as pd

from .query import CaseDB


def build_timeline(
    db: CaseDB,
    start=None,
    end=None,
    host: str | None = None,
    channel: str | None = None,
    event_id: int | list[int] | None = None,
) -> pd.DataFrame:
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
    return db.sql(
        "SELECT time_created, host, computer, channel, event_id, provider_name, "
        "process_id, user_sid, event_data, source_file "
        f"FROM events {where} ORDER BY time_created",
        params,
    )
