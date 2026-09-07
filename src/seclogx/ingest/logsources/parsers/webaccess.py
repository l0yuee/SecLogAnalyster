"""Parse nginx/Apache/Tomcat Common/Combined Log Format access logs into
`web_logs` rows.

Common Log Format (CLF) and the Combined variant (CLF + referer + user
agent) are effectively identical across nginx, Apache, and Tomcat's default
access log patterns -- there is no reliable way to tell the three apart
from the log line alone, only from path/filename context (see
`sniff.guess_web_log_type`, a heuristic, not a detection).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..sniff import _decode_lines

_CLF_RE = re.compile(
    r'^(?P<client_ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
# A whole file almost always shares one UTC offset, so the tzinfo objects
# are built once and reused rather than per row.
_TZ_CACHE: dict[str, timezone] = {}


def _tzinfo(offset: str) -> timezone:
    tz = _TZ_CACHE.get(offset)
    if tz is None:
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        tz = timezone(-delta if offset[0] == "-" else delta)
        _TZ_CACHE[offset] = tz
    return tz


def _parse_time_strptime(raw: str) -> str | None:
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None


def _parse_time(raw: str) -> str | None:
    """Parse a CLF timestamp -- e.g. `10/Oct/2023:13:55:36 +0000`.

    This is the single hottest operation in a large web-log ingest (one
    call per line, and access logs are the family that realistically
    reaches billions of lines), so the standard fixed-width shape is read
    by slicing instead of `datetime.strptime`, which rebuilds a
    locale-aware regex match and format-cache lookup on every call --
    measured 4.5x faster. `datetime(...)` still does the field validation,
    so an impossible date is rejected exactly as before, and anything not
    matching the fixed-width shape (unpadded fields, a missing offset)
    falls back to `strptime` rather than being rejected."""
    try:
        if raw[2] != "/" or raw[6] != "/" or raw[11] != ":" or raw[14] != ":" or raw[17] != ":" or raw[20] != " ":
            return _parse_time_strptime(raw)
        return datetime(
            int(raw[7:11]), _MONTHS[raw[3:6]], int(raw[0:2]),
            int(raw[12:14]), int(raw[15:17]), int(raw[18:20]),
            tzinfo=_tzinfo(raw[21:26]),
        ).isoformat()
    except (KeyError, ValueError, IndexError):
        return _parse_time_strptime(raw)


def parse_web_access_file(path: Path, host: str, log_type: str) -> tuple[list[dict], int, int]:
    """Returns (rows, ok_count, error_count). A line that doesn't match CLF/
    Combined is counted as an error, not silently skipped."""
    raw = path.read_bytes()
    rows: list[dict] = []
    error_count = 0

    for line in _decode_lines(raw):
        if not line.strip():
            continue
        m = _CLF_RE.match(line)
        if not m:
            error_count += 1
            continue

        request = m.group("request")
        method = uri = protocol_version = None
        req_parts = request.split(" ")
        if len(req_parts) == 3:
            method, uri, protocol_version = req_parts
        elif len(req_parts) == 2:
            method, uri = req_parts
        elif request and request != "-":
            uri = request

        uri_stem, _, uri_query = (uri or "").partition("?")

        user = m.group("user")
        bytes_sent_raw = m.group("bytes")
        rows.append(
            {
                "host": host,
                "log_type": log_type,
                "time_created": _parse_time(m.group("time")),
                "client_ip": m.group("client_ip"),
                "server_ip": None,
                "server_port": None,
                "method": method,
                "uri_stem": uri_stem or None,
                "uri_query": uri_query or None,
                "protocol_version": protocol_version,
                "status": int(m.group("status")),
                "substatus": None,
                "win32_status": None,
                "bytes_sent": None if bytes_sent_raw == "-" else int(bytes_sent_raw),
                "bytes_received": None,
                "time_taken_ms": None,
                "username": None if user in ("-", "") else user,
                "user_agent": m.group("user_agent"),
                "referer": None if m.group("referer") == "-" else m.group("referer"),
                "extra": None,
            }
        )

    return rows, len(rows), error_count
