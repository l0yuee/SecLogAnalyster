"""Parse IIS W3C Extended Log Format files into `web_logs` rows.

The format is self-describing (a `#Fields:` header line names the
space-delimited columns actually enabled for that site), so this reads the
header rather than assuming a fixed field order/set -- IIS admins routinely
customize which fields are logged.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .sniff import _decode_lines

_FIELD_MAP = {
    "s-ip": "server_ip",
    "cs-method": "method",
    "cs-uri-stem": "uri_stem",
    "cs-uri-query": "uri_query",
    "s-port": "server_port",
    "cs-username": "username",
    "c-ip": "client_ip",
    "cs(User-Agent)": "user_agent",
    "cs(Referer)": "referer",
    "sc-status": "status",
    "sc-substatus": "substatus",
    "sc-win32-status": "win32_status",
    "time-taken": "time_taken_ms",
    "sc-bytes": "bytes_sent",
    "cs-bytes": "bytes_received",
    "cs-version": "protocol_version",
}
_INT_FIELDS = {"status", "substatus", "win32_status", "time_taken_ms", "bytes_sent", "bytes_received"}
_HANDLED_SOURCE_FIELDS = set(_FIELD_MAP) | {"date", "time"}


def _read_all_text(path: Path) -> str:
    raw = path.read_bytes()
    return "\n".join(_decode_lines(raw))


def parse_iis_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    """Returns (rows, ok_count, error_count). Never raises -- a line that
    doesn't match the current `#Fields:` header is counted as an error, not
    silently skipped."""
    text = _read_all_text(path)
    fields: list[str] | None = None
    rows: list[dict] = []
    error_count = 0

    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:") :].strip().split()
            continue
        if line.startswith("#"):
            continue
        if fields is None:
            error_count += 1
            continue
        parts = line.split(" ")
        if len(parts) != len(fields):
            error_count += 1
            continue
        raw_rec = dict(zip(fields, parts))
        rows.append(_normalize_record(raw_rec, host))

    return rows, len(rows), error_count


def _normalize_record(raw_rec: dict, host: str) -> dict:
    row: dict = {
        "host": host,
        "log_type": "iis",
        "server_ip": None,
        "server_port": None,
        "method": None,
        "uri_stem": None,
        "uri_query": None,
        "protocol_version": None,
        "status": None,
        "substatus": None,
        "win32_status": None,
        "bytes_sent": None,
        "bytes_received": None,
        "time_taken_ms": None,
        "username": None,
        "client_ip": None,
        "user_agent": None,
        "referer": None,
    }

    date_part = raw_rec.get("date")
    time_part = raw_rec.get("time")
    time_created = None
    if date_part and time_part and date_part != "-" and time_part != "-":
        try:
            time_created = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S").isoformat()
        except ValueError:
            time_created = None
    row["time_created"] = time_created

    extra = {}
    for src_field, value in raw_rec.items():
        if value == "-":
            value = None
        if src_field in _FIELD_MAP:
            dest = _FIELD_MAP[src_field]
            if value is not None and dest in _INT_FIELDS:
                try:
                    value = int(value)
                except ValueError:
                    value = None
            row[dest] = value
        elif src_field not in _HANDLED_SOURCE_FIELDS:
            extra[src_field] = value

    row["extra"] = json.dumps(extra) if extra else None
    return row
