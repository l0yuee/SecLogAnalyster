"""Parse the *error/diagnostic* log category of web applications, as
distinct from the *access* log category handled by `iis.py`/`webaccess.py`.

Unlike access logs, nginx/Apache/Tomcat error-log format is
engine-specific and unambiguous (unlike Common/Combined access-log
format, which is byte-identical across all three) -- so `log_type` here
comes directly from which regex matched in `sniff.py`, not a path/filename
guess.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from ..sniff import _decode_lines

_NGINX_ERROR_RE = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<severity>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): (?:\*\d+ )?(?P<message>.*)$"
)
_NGINX_CLIENT_RE = re.compile(r"client: ([^,]+)")

_APACHE_ERROR_RE = re.compile(
    r"^\[(?P<time>\w{3} \w{3} [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[(?:[\w-]+:)?(?P<severity>\w+)\]"
    r"(?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?"
    r"(?: \[client (?P<client>[^\]]+)\])?"
    r" (?P<message>.*)$"
)

_TOMCAT_ERROR_RE = re.compile(
    r"^(?P<time>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"(?P<severity>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST|ALL) "
    r"\[(?P<thread>[^\]]+)\] (?P<logger>\S+) (?P<message>.*)$"
)
_TOMCAT_MAX_CONTINUATION_LINES = 200  # cap a single entry's attached stack trace

_HTTPERR_FIELD_MAP = {
    "c-ip": "client_ip",
    "c-port": "client_port",
    "s-ip": "server_ip",
    "s-port": "server_port",
    "cs-version": "protocol_version",
    "cs-method": "method",
    "cs-uri": "uri",
    "sc-status": "status",
}
_HTTPERR_INT_FIELDS = {"status"}
_HTTPERR_HANDLED_SOURCE_FIELDS = set(_HTTPERR_FIELD_MAP) | {"date", "time", "s-reason"}


def _empty_row(host: str, log_type: str) -> dict:
    return {
        "host": host,
        "log_type": log_type,
        "time_created": None,
        "severity": None,
        "pid_or_thread": None,
        "client_ip": None,
        "client_port": None,
        "server_ip": None,
        "server_port": None,
        "protocol_version": None,
        "method": None,
        "uri": None,
        "status": None,
        "logger": None,
        "message": None,
        "extra": None,
    }


def parse_nginx_error_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue
        m = _NGINX_ERROR_RE.match(line)
        if not m:
            error_count += 1
            continue
        row = _empty_row(host, "nginx")
        try:
            row["time_created"] = datetime.strptime(m.group("time"), "%Y/%m/%d %H:%M:%S").isoformat()
        except ValueError:
            pass
        row["severity"] = m.group("severity")
        row["pid_or_thread"] = f"{m.group('pid')}#{m.group('tid')}"
        row["message"] = m.group("message")
        client_m = _NGINX_CLIENT_RE.search(row["message"])
        if client_m:
            row["client_ip"] = client_m.group(1).strip()
        rows.append(row)
    return rows, len(rows), error_count


def parse_apache_error_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue
        m = _APACHE_ERROR_RE.match(line)
        if not m:
            error_count += 1
            continue
        row = _empty_row(host, "apache")
        time_created = None
        for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                time_created = datetime.strptime(m.group("time"), fmt).isoformat()
                break
            except ValueError:
                continue
        row["time_created"] = time_created
        row["severity"] = m.group("severity")
        row["pid_or_thread"] = m.group("pid")
        client = m.group("client")
        if client:
            ip, sep, port = client.rpartition(":")
            if sep and port.isdigit():
                row["client_ip"], row["client_port"] = ip, port
            else:
                row["client_ip"] = client
        row["message"] = m.group("message")
        rows.append(row)
    return rows, len(rows), error_count


def parse_tomcat_error_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    current: dict | None = None
    continuation_count = 0

    for line in _decode_lines(path.read_bytes()):
        m = _TOMCAT_ERROR_RE.match(line)
        if m:
            current = _empty_row(host, "tomcat")
            try:
                current["time_created"] = datetime.strptime(m.group("time"), "%d-%b-%Y %H:%M:%S.%f").isoformat()
            except ValueError:
                pass
            current["severity"] = m.group("severity")
            current["pid_or_thread"] = m.group("thread")
            current["logger"] = m.group("logger")
            current["message"] = m.group("message")
            rows.append(current)
            continuation_count = 0
            continue
        if not line.strip():
            continue
        if current is not None and continuation_count < _TOMCAT_MAX_CONTINUATION_LINES:
            current["message"] = f"{current['message']}\n{line}"
            continuation_count += 1
        else:
            error_count += 1

    return rows, len(rows), error_count


def parse_iis_httperr_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    fields: list[str] | None = None
    rows: list[dict] = []
    error_count = 0

    for line in _decode_lines(path.read_bytes()):
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
        rec = dict(zip(fields, parts))
        rows.append(_normalize_httperr_record(rec, host))

    return rows, len(rows), error_count


def _normalize_httperr_record(rec: dict, host: str) -> dict:
    row = _empty_row(host, "iis_httperr")

    date_part = rec.get("date")
    time_part = rec.get("time")
    if date_part and time_part and date_part != "-" and time_part != "-":
        try:
            row["time_created"] = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S").isoformat()
        except ValueError:
            pass

    extra = {}
    for src_field, value in rec.items():
        if value == "-":
            value = None
        if src_field in _HTTPERR_FIELD_MAP:
            dest = _HTTPERR_FIELD_MAP[src_field]
            if value is not None and dest in _HTTPERR_INT_FIELDS:
                try:
                    value = int(value)
                except ValueError:
                    value = None
            row[dest] = value
        elif src_field == "s-reason":
            row["message"] = value
        elif src_field not in _HTTPERR_HANDLED_SOURCE_FIELDS:
            extra[src_field] = value

    row["extra"] = json.dumps(extra) if extra else None
    return row
