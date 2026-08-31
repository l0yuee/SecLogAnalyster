"""Parse generic syslog into `syslog` rows: BSD/RFC-3164 (with or without a
`<PRI>` prefix -- most real-world `/var/log/syslog`/`messages`/`auth.log`
files use rsyslog's default template, which omits it) and RFC 5424.

`auth.log`/`secure` are not a separate format or sniff kind: they're
syslog-envelope lines like `/var/log/syslog`, just with recognizable
program names (sshd, sudo, su, useradd, ...) and message shapes in them.
`extract_auth_events()` below is the non-ingest-time equivalent of
`Case.suspicious_tasks()` (see `parsers/scheduled_tasks.py`): a heuristic
view computed from `syslog` rows already in the lake, not its own table --
see `docs/known_limitations.md` for exactly which SSH/sudo/PAM/account-
management message shapes it recognizes.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ..sniff import _decode_lines

_FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
_SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}

_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s"
    r"(?P<timestamp>\S+)\s(?P<host>\S+)\s(?P<app>\S+)\s(?P<procid>\S+)\s(?P<msgid>\S+)\s"
    r"(?P<sd>-|(?:\[[^\]]*\])+)(?:\s(?P<msg>.*))?$"
)
_BSD_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_SD_ELEMENT_RE = re.compile(r"\[(?P<id>[^\s\]]+)(?P<params>(?:\s+[^\s=]+=\"(?:[^\"\\]|\\.)*\")*)\]")
_SD_PARAM_RE = re.compile(r'([^\s=]+)="((?:[^"\\]|\\.)*)"')


def _pri_to_facility_severity(pri_text: str | None) -> tuple[str | None, str | None]:
    if pri_text is None:
        return None, None
    try:
        pri = int(pri_text)
    except ValueError:
        return None, None
    facility_num, severity_num = divmod(pri, 8)
    facility = _FACILITIES[facility_num] if 0 <= facility_num < len(_FACILITIES) else None
    severity = _SEVERITIES[severity_num] if 0 <= severity_num < len(_SEVERITIES) else None
    return facility, severity


def _parse_structured_data(sd: str) -> str | None:
    if sd == "-":
        return None
    elements = {}
    for m in _SD_ELEMENT_RE.finditer(sd):
        params = {pm.group(1): pm.group(2) for pm in _SD_PARAM_RE.finditer(m.group("params"))}
        elements[m.group("id")] = params
    return json.dumps(elements) if elements else None


def _parse_bsd_timestamp(mon: str, day: str, time_str: str, year: int) -> str | None:
    month_num = _MONTHS.get(mon[:3].title())
    if month_num is None:
        return None
    try:
        return datetime.strptime(f"{year}-{month_num:02d}-{int(day):02d} {time_str}", "%Y-%m-%d %H:%M:%S").isoformat()
    except ValueError:
        return None


def _parse_5424_timestamp(raw: str) -> str | None:
    if raw == "-":
        return None
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return None


def parse_syslog_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    """Returns (rows, ok_count, error_count). A line matching neither the
    RFC5424 nor the BSD envelope is counted as an error, not silently
    dropped -- consistent with every other line-oriented parser here.
    BSD-format lines have no year in their timestamp; it's inferred from
    the file's mtime (best-effort, same spirit as `guess_web_log_type`'s
    filename heuristic -- see docs/known_limitations.md)."""
    try:
        year = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).year
    except OSError:
        year = datetime.now(timezone.utc).year

    rows: list[dict] = []
    error_count = 0

    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue

        m = _RFC5424_RE.match(line)
        if m:
            facility, severity = _pri_to_facility_severity(m.group("pri"))
            rows.append(
                {
                    "host": host,
                    "time_created": _parse_5424_timestamp(m.group("timestamp")),
                    "hostname": m.group("host"),
                    "facility": facility,
                    "severity": severity,
                    "app_name": None if m.group("app") == "-" else m.group("app"),
                    "proc_id": None if m.group("procid") == "-" else m.group("procid"),
                    "msg_id": None if m.group("msgid") == "-" else m.group("msgid"),
                    "message": m.group("msg") or "",
                    "structured_data": _parse_structured_data(m.group("sd")),
                }
            )
            continue

        m = _BSD_RE.match(line)
        if m:
            facility, severity = _pri_to_facility_severity(m.group("pri"))
            rows.append(
                {
                    "host": host,
                    "time_created": _parse_bsd_timestamp(m.group("mon"), m.group("day"), m.group("time"), year),
                    "hostname": m.group("host"),
                    "facility": facility,
                    "severity": severity,
                    "app_name": m.group("tag"),
                    "proc_id": m.group("pid"),
                    "msg_id": None,
                    "message": m.group("msg"),
                    "structured_data": None,
                }
            )
            continue

        error_count += 1

    return rows, len(rows), error_count


# -- derived heuristic: Case.auth_events() ------------------------------------
# Recognized message shapes: OpenSSH (Accepted/Failed/Invalid user/
# disconnects), sudo COMMAND lines, PAM session open/close (any service --
# su, sudo, sshd, login, ...), and shadow-utils account management
# (useradd/userdel/usermod/groupadd/groupdel/passwd). Not exhaustive of
# every SSH daemon or PAM configuration -- see docs/known_limitations.md.
_SSH_ACCEPTED_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_FAILED_RE = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_SSH_DISCONNECT_RE = re.compile(
    r"^(?:Received disconnect from|Disconnected from|Connection closed by)\s+"
    r"(?:user\s+)?(?:invalid user\s+)?(?P<user>\S+\s+)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?\bCOMMAND=(?P<command>.*)$")
_PAM_SESSION_RE = re.compile(r"pam_unix\([\w.-]+:session\):\s*session (?P<state>opened|closed) for user (?P<user>\S+)")
_ACCOUNT_MGMT_TAGS = {"useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd"}
_ACCOUNT_USER_NAME_RE = re.compile(r"name=([^,\s]+)")
_ACCOUNT_USER_QUOTED_RE = re.compile(r"'([^']+)'")

_AUTH_EVENT_COLUMNS = [
    "time_created", "host", "event_type", "user", "source_ip", "source_port",
    "auth_method", "command", "message", "app_name",
]


def _extract_account_user(message: str) -> str | None:
    m = _ACCOUNT_USER_NAME_RE.search(message)
    if m:
        return m.group(1)
    m = _ACCOUNT_USER_QUOTED_RE.search(message)
    return m.group(1) if m else None


def _extract_one(app_name: str | None, message: str | None) -> dict | None:
    app = (app_name or "").lower()
    msg = message or ""

    if "sshd" in app:
        m = _SSH_ACCEPTED_RE.match(msg)
        if m:
            return {
                "event_type": "ssh_accepted", "user": m.group("user"), "source_ip": m.group("ip"),
                "source_port": m.group("port"), "auth_method": m.group("method"), "command": None,
            }
        m = _SSH_FAILED_RE.match(msg)
        if m:
            return {
                "event_type": "ssh_failed", "user": m.group("user"), "source_ip": m.group("ip"),
                "source_port": m.group("port"), "auth_method": m.group("method"), "command": None,
            }
        m = _SSH_INVALID_USER_RE.match(msg)
        if m:
            return {
                "event_type": "ssh_invalid_user", "user": m.group("user"), "source_ip": m.group("ip"),
                "source_port": None, "auth_method": None, "command": None,
            }
        m = _SSH_DISCONNECT_RE.match(msg)
        if m:
            user = m.group("user")
            return {
                "event_type": "ssh_disconnected", "user": user.strip() if user else None,
                "source_ip": m.group("ip"), "source_port": None, "auth_method": None, "command": None,
            }

    if app == "sudo":
        m = _SUDO_RE.match(msg)
        if m:
            return {
                "event_type": "sudo_command", "user": m.group("user"), "source_ip": None,
                "source_port": None, "auth_method": None, "command": m.group("command").strip(),
            }

    m = _PAM_SESSION_RE.search(msg)
    if m:
        return {
            "event_type": f"session_{m.group('state')}", "user": m.group("user"), "source_ip": None,
            "source_port": None, "auth_method": None, "command": None,
        }

    if app in _ACCOUNT_MGMT_TAGS:
        return {
            "event_type": "account_management", "user": _extract_account_user(msg), "source_ip": None,
            "source_port": None, "auth_method": None, "command": msg,
        }

    return None


def extract_auth_events(df: pd.DataFrame) -> pd.DataFrame:
    """Derived, curated view over an already-ingested `syslog` DataFrame --
    see the module docstring for what this recognizes. Rows that don't
    match a recognized shape are excluded, mirroring how
    `Case.suspicious_tasks()` filters `scheduled_tasks` down to a flagged
    subset rather than returning everything."""
    records = []
    for row in df.itertuples(index=False):
        extracted = _extract_one(getattr(row, "app_name", None), getattr(row, "message", None))
        if extracted is None:
            continue
        records.append(
            {
                "time_created": getattr(row, "time_created", None),
                "host": getattr(row, "host", None),
                "app_name": getattr(row, "app_name", None),
                "message": getattr(row, "message", None),
                **extracted,
            }
        )
    return pd.DataFrame(records, columns=_AUTH_EVENT_COLUMNS)
