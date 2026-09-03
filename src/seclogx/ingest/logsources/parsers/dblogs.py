"""Parse database server logs: MySQL/MariaDB (error, general query, and
slow query logs), PostgreSQL (stderr-format log), MSSQL (ERRORLOG), and
Oracle (alert log).

Each sub-format gets its own `parse_*_file` function -- same shape as
`weberror.py`'s per-engine parsers (`(rows, ok_count, error_count)`,
built on `_decode_lines`, unmatched/unparseable lines counted as errors
rather than silently dropped) -- but all map into the single shared
`db_logs` row schema via `_empty_row`, discriminated by `log_type`. See
docs/known_limitations.md for the content-sniffing caveats specific to
each sub-format (PostgreSQL's configurable `log_line_prefix`, MySQL
general/slow log marker-line dependence, Oracle alert log banner-before-
timestamp).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from ..sniff import _decode_lines

# -- MySQL/MariaDB error log -------------------------------------------------

# 5.7+/8.0 format: "<iso-time> <thread> [<Level>] [<MY-code>] [<Subsystem>] msg"
# -- the error code and subsystem tag are each independently optional.
_MYSQL_ERROR_NEW_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(?P<thread>\d+)\s+"
    r"\[(?P<severity>System|Note|Warning|ERROR)\]"
    r"(?:\s+\[(?P<code>MY-\d+)\])?"
    r"(?:\s+\[(?P<component>[^\]]+)\])?"
    r"\s+(?P<message>.*)$"
)
# Pre-5.7 format: "<yymmdd> <hh:mm:ss> [<Level>] msg" -- no thread id/error code/tag.
_MYSQL_ERROR_OLD_RE = re.compile(
    r"^(?P<time>\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+\[(?P<severity>Note|Warning|ERROR)\]\s+(?P<message>.*)$"
)

# -- MySQL/MariaDB general query log -----------------------------------------

_MYSQL_GENERAL_HEADER_RE = re.compile(r"^Time\s+Id\s+Command\s+Argument\s*$")
# A new entry repeats the ISO timestamp; a continuation entry (same
# connection, next statement) omits it -- only the leading tab + Id +
# Command is guaranteed.
_MYSQL_GENERAL_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)?\t\s*(?P<id>\d+)\s+"
    r"(?P<command>[A-Za-z]+(?: [A-Za-z]+)?)(?:\t(?P<argument>.*))?$"
)

# -- MySQL/MariaDB slow query log --------------------------------------------

_SLOW_TIME_RE = re.compile(r"^# Time:\s*(?P<time>\S+)")
_SLOW_USER_HOST_RE = re.compile(
    r"^# User@Host:\s*(?P<user>[^\[\s]*)\[[^\]]*\]\s*@\s*(?P<hostname>[^\[]*)\[(?P<ip>[^\]]*)\]\s*Id:\s*(?P<id>\d+)"
)
_SLOW_QUERY_TIME_RE = re.compile(
    r"^# Query_time:\s*(?P<query_time>[\d.]+)\s+Lock_time:\s*(?P<lock_time>[\d.]+)\s+"
    r"Rows_sent:\s*(?P<rows_sent>\d+)\s+Rows_examined:\s*(?P<rows_examined>\d+)"
)

# -- PostgreSQL ---------------------------------------------------------------

# Covers the common `%m [%p] %q%u@%d ` log_line_prefix shape -- not
# arbitrary custom prefixes (see docs/known_limitations.md).
_POSTGRESQL_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(?P<tz>\S+)\s+\[(?P<pid>\d+)\]\s*"
    r"(?:(?P<user>[^\s@]+)@(?P<database>\S+)\s+)?"
    r"(?P<severity>LOG|ERROR|WARNING|FATAL|PANIC|NOTICE|DETAIL|HINT|STATEMENT|DEBUG[1-5]?):\s+(?P<message>.*)$"
)

# -- MSSQL ERRORLOG -----------------------------------------------------------

_MSSQL_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d{2})\s+(?P<component>\S+)\s{2,}(?P<message>.*)$"
)
_MSSQL_SPID_RE = re.compile(r"^spid(?P<num>\d+)")

# -- Oracle alert log ----------------------------------------------------------

_ORACLE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2}$")
_ORACLE_ERROR_CODE_RE = re.compile(r"ORA-\d{5}")
_ORACLE_MAX_CONTINUATION_LINES = 200  # cap a single alert entry's attached detail lines


def _empty_row(host: str, log_type: str) -> dict:
    return {
        "host": host,
        "log_type": log_type,
        "time_created": None,
        "severity": None,
        "component": None,
        "error_code": None,
        "thread_id": None,
        "user_name": None,
        "database_name": None,
        "client_address": None,
        "query_time_sec": None,
        "rows_examined": None,
        "message": None,
        "extra": None,
    }


def parse_mysql_error_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue
        m = _MYSQL_ERROR_NEW_RE.match(line)
        if m:
            row = _empty_row(host, "mysql_error")
            try:
                row["time_created"] = datetime.strptime(m.group("time"), "%Y-%m-%dT%H:%M:%S.%fZ").isoformat()
            except ValueError:
                pass
            row["thread_id"] = m.group("thread")
            row["severity"] = m.group("severity")
            row["error_code"] = m.group("code")
            row["component"] = m.group("component")
            row["message"] = m.group("message")
            rows.append(row)
            continue
        m = _MYSQL_ERROR_OLD_RE.match(line)
        if m:
            row = _empty_row(host, "mysql_error")
            try:
                row["time_created"] = datetime.strptime(m.group("time"), "%y%m%d %H:%M:%S").isoformat()
            except ValueError:
                pass
            row["severity"] = m.group("severity")
            row["message"] = m.group("message")
            rows.append(row)
            continue
        error_count += 1
    return rows, len(rows), error_count


def parse_mysql_general_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    last_timestamp: str | None = None
    for line in _decode_lines(path.read_bytes()):
        if not line.strip() or _MYSQL_GENERAL_HEADER_RE.match(line):
            continue
        m = _MYSQL_GENERAL_RE.match(line)
        if not m:
            error_count += 1
            continue
        if m.group("time"):
            try:
                last_timestamp = datetime.strptime(m.group("time"), "%Y-%m-%dT%H:%M:%S.%fZ").isoformat()
            except ValueError:
                pass
        row = _empty_row(host, "mysql_general")
        row["time_created"] = last_timestamp
        row["thread_id"] = m.group("id")
        row["component"] = m.group("command")
        argument = (m.group("argument") or "").strip()
        row["message"] = argument or None
        rows.append(row)
    return rows, len(rows), error_count


def parse_mysql_slow_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    current: dict | None = None
    sql_lines: list[str] = []

    def flush() -> None:
        if current is not None:
            text = "\n".join(sql_lines).strip()
            current["message"] = text or None
            rows.append(current)

    for line in _decode_lines(path.read_bytes()):
        m_time = _SLOW_TIME_RE.match(line)
        if m_time:
            flush()
            current = _empty_row(host, "mysql_slow")
            try:
                current["time_created"] = datetime.strptime(m_time.group("time"), "%Y-%m-%dT%H:%M:%S.%fZ").isoformat()
            except ValueError:
                pass
            sql_lines = []
            continue

        if current is None:
            if line.strip():
                error_count += 1
            continue

        m_user = _SLOW_USER_HOST_RE.match(line)
        if m_user:
            current["user_name"] = m_user.group("user") or None
            hostname = (m_user.group("hostname") or "").strip()
            ip = (m_user.group("ip") or "").strip()
            current["client_address"] = hostname or ip or None
            current["thread_id"] = m_user.group("id")
            continue

        m_qt = _SLOW_QUERY_TIME_RE.match(line)
        if m_qt:
            try:
                current["query_time_sec"] = float(m_qt.group("query_time"))
            except ValueError:
                pass
            try:
                current["rows_examined"] = int(m_qt.group("rows_examined"))
            except ValueError:
                pass
            current["extra"] = json.dumps(
                {"lock_time": m_qt.group("lock_time"), "rows_sent": m_qt.group("rows_sent")}
            )
            continue

        if line.startswith("#"):
            continue
        if line.strip().startswith("SET timestamp="):
            continue

        sql_lines.append(line)

    flush()
    return rows, len(rows), error_count


def parse_postgresql_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue
        m = _POSTGRESQL_RE.match(line)
        if not m:
            error_count += 1
            continue
        row = _empty_row(host, "postgresql")
        try:
            row["time_created"] = datetime.strptime(m.group("time"), "%Y-%m-%d %H:%M:%S.%f").isoformat()
        except ValueError:
            pass
        row["thread_id"] = m.group("pid")
        row["user_name"] = m.group("user")
        row["database_name"] = m.group("database")
        row["severity"] = m.group("severity")
        row["message"] = m.group("message")
        rows.append(row)
    return rows, len(rows), error_count


def parse_mssql_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue
        m = _MSSQL_RE.match(line)
        if not m:
            error_count += 1
            continue
        row = _empty_row(host, "mssql")
        try:
            row["time_created"] = datetime.strptime(
                f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S.%f"
            ).isoformat()
        except ValueError:
            pass
        component = m.group("component")
        row["component"] = component
        spid_m = _MSSQL_SPID_RE.match(component)
        if spid_m:
            row["thread_id"] = spid_m.group("num")
        row["message"] = m.group("message")
        rows.append(row)
    return rows, len(rows), error_count


def parse_oracle_alert_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    error_count = 0
    current: dict | None = None
    message_lines: list[str] = []
    continuation_count = 0

    def flush() -> None:
        if current is not None:
            text = "\n".join(message_lines).strip()
            current["message"] = text or None
            code_m = _ORACLE_ERROR_CODE_RE.search(text)
            if code_m:
                current["error_code"] = code_m.group(0)
            rows.append(current)

    for line in _decode_lines(path.read_bytes()):
        stripped = line.strip()
        if _ORACLE_TIMESTAMP_RE.match(stripped):
            flush()
            current = _empty_row(host, "oracle")
            try:
                current["time_created"] = datetime.fromisoformat(stripped).isoformat()
            except ValueError:
                pass
            message_lines = []
            continuation_count = 0
            continue

        if not stripped:
            continue
        if current is None:
            error_count += 1
            continue
        if continuation_count < _ORACLE_MAX_CONTINUATION_LINES:
            message_lines.append(line)
            continuation_count += 1
        else:
            error_count += 1

    flush()
    return rows, len(rows), error_count
