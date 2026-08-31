"""Parse systemd journal export format (`journalctl -o json`) into
`journal_logs` rows -- one JSON object per line. This is the portable,
textual export format, not the binary journal itself (`/var/log/journal/**`
or `/run/log/journal/**`), which isn't parsed here (see
docs/known_limitations.md).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..sniff import _decode_lines

_PROMOTED_FIELDS = {
    "_HOSTNAME": "hostname",
    "_SYSTEMD_UNIT": "unit",
    "SYSLOG_IDENTIFIER": "syslog_identifier",
    "PRIORITY": "priority",
    "_PID": "pid",
    "_UID": "uid",
    "_COMM": "comm",
    "_EXE": "exe",
    "MESSAGE": "message",
}
_DROPPED_FIELDS = {"__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP"}


def _scalar(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _parse_realtime_timestamp(raw) -> str | None:
    try:
        micros = int(raw)
    except (TypeError, ValueError):
        return None
    try:
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_journal_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    """Returns (rows, ok_count, error_count). A line that isn't a valid
    JSON object is counted as an error, not silently dropped."""
    rows: list[dict] = []
    error_count = 0

    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue

        try:
            entry = json.loads(line)
        except ValueError:
            error_count += 1
            continue
        if not isinstance(entry, dict):
            error_count += 1
            continue

        row = {
            "host": host,
            "time_created": _parse_realtime_timestamp(entry.get("__REALTIME_TIMESTAMP")),
        }
        remainder = {k: v for k, v in entry.items() if k not in _DROPPED_FIELDS}
        for src_field, dest in _PROMOTED_FIELDS.items():
            row[dest] = _scalar(remainder.pop(src_field, None))
        row["fields"] = json.dumps(remainder) if remainder else None
        rows.append(row)

    return rows, len(rows), error_count
