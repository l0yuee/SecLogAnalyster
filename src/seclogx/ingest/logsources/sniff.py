"""Classify a non-.evtx file discovered under a source path into one of the
log families this module supports, by peeking at its content rather than
trusting its name or extension -- forensic acquisitions routinely rename or
relocate files (e.g. exporting a Task Scheduler task definition, which has
no extension on a live system, as `<name>.xml`).

Classification never raises for an unreadable/binary/unrecognized file; it
returns `None` ("unknown"), which the caller reports explicitly rather than
silently skipping (see ingest/logsources/orchestrator.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...textdecode import decode_text as _decode_text

KIND_SCHEDULED_TASK = "scheduled_task"
KIND_IIS = "iis"
KIND_IIS_HTTPERR = "iis_httperr"
KIND_EXCHANGE_MESSAGE_TRACKING = "exchange_message_tracking"
KIND_EXCHANGE_GENERIC = "exchange_generic"
KIND_WEB_ACCESS = "web_access"
KIND_WEB_ERROR_NGINX = "web_error_nginx"
KIND_WEB_ERROR_APACHE = "web_error_apache"
KIND_WEB_ERROR_TOMCAT = "web_error_tomcat"
KIND_SYSLOG = "syslog"
KIND_AUDITD = "auditd"
KIND_JOURNAL_EXPORT = "journal_export"
KIND_MYSQL_ERROR = "mysql_error"
KIND_MYSQL_GENERAL = "mysql_general"
KIND_MYSQL_SLOW = "mysql_slow"
KIND_POSTGRESQL = "postgresql"
KIND_MSSQL = "mssql"
KIND_ORACLE_ALERT = "oracle_alert"
KIND_REGISTRY_HIVE = "registry_hive"
KIND_QCLOUD_YDSERVICE = "qcloud_ydservice"
KIND_QCLOUD_GO = "qcloud_go"
KIND_QCLOUD_SCANNER = "qcloud_scanner"
KIND_QCLOUD_YDEYES = "qcloud_ydeyes"

WEB_ERROR_KINDS = {KIND_WEB_ERROR_NGINX: "nginx", KIND_WEB_ERROR_APACHE: "apache", KIND_WEB_ERROR_TOMCAT: "tomcat"}

_PEEK_BYTES = 16 * 1024
_TASK_XMLNS_RE = re.compile(rb"xmlns\s*=\s*[\"']http://schemas\.microsoft\.com/windows/\d{4}/\d{2}/mit/task[\"']")
_CLF_RE = re.compile(rb'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} (?:\d+|-)')
_NGINX_ERROR_RE = re.compile(rb"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(?:emerg|alert|crit|error|warn|notice|info|debug)\] \d+#\d+:")
_APACHE_ERROR_RE = re.compile(rb"^\[\w{3} \w{3} [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}\] \[")
_TOMCAT_ERROR_RE = re.compile(rb"^\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3} (?:SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST|ALL)\b")
_AUDITD_RE = re.compile(rb"^type=\S+\s+msg=audit\(\d+\.\d+:\d+\):")
_SYSLOG_5424_RE = re.compile(rb"^<\d{1,3}>\d\s")
_SYSLOG_BSD_RE = re.compile(rb"^(?:<\d{1,3}>)?\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s\S+\s")

# Database logs. mysql_slow/mysql_general aren't reliably identifiable from
# a single first data line (slow log entries open with a '#'-prefixed
# marker; general log continuation lines don't repeat the timestamp), so
# those are detected via marker/header lines in the scan loop below instead
# -- see KIND_MYSQL_SLOW/KIND_MYSQL_GENERAL handling in classify_file.
_MYSQL_ERROR_NEW_RE = re.compile(rb"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\d+\s+\[(?:System|Note|Warning|ERROR)\]")
_MYSQL_ERROR_OLD_RE = re.compile(rb"^\d{6}\s+\d{1,2}:\d{2}:\d{2}\s+\[(?:Note|Warning|ERROR)\]")
_MYSQL_SLOW_MARKER_RE = re.compile(rb"^# (?:Time|Query_time):")
_MYSQL_GENERAL_HEADER_RE = re.compile(rb"^Time\s+Id\s+Command\s+Argument\s*$")
_POSTGRESQL_RE = re.compile(
    rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+\[\d+\].*\s(?:LOG|ERROR|WARNING|FATAL|PANIC|NOTICE|DETAIL|HINT|STATEMENT|DEBUG[1-5]?):\s"
)
_MSSQL_RE = re.compile(rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{2}\s+\S+\s{2,}\S")
_ORACLE_ALERT_RE = re.compile(rb"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2}$")

# Tencent Cloud Host Security (YunJing / Tencent CWPP).  The YDService
# shape is distinctive enough to identify from content alone.  The other
# three are common logging shapes, so they additionally require a YunJing
# path/name or a product-specific marker in the 16KB peek.
_QCLOUD_YDSERVICE_RE = re.compile(
    rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \d+ \d+ [A-Za-z]+ [^: ]+:\d+ .*$"
)
_QCLOUD_GO_RE = re.compile(
    rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\[[^]]+\]\[[^]:]+:\d+\].*$"
)
_QCLOUD_SCANNER_RE = re.compile(
    rb"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[[^]]+\] .*$"
)
_QCLOUD_YDEYES_RE = re.compile(rb"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] .*$")
_QCLOUD_PRODUCT_MARKERS = (
    b"yunjing",
    b"tencent cwpp",
    b"ydservice",
    b"ydlive",
    b"ydflame",
    b"ydquara",
    b"yhvs",
    b"blackiplist",
    b"/var/run/yd_",
)

_MESSAGE_TRACKING_FIELDS = {"message-id", "recipient-address"}
# journald's "trusted", double-underscore-prefixed fields -- reliable,
# format-unique signal for `journalctl -o json` export lines (as opposed
# to any other line-delimited JSON log a source directory might contain).
_JOURNAL_EXPORT_MARKERS = {"__REALTIME_TIMESTAMP", "__CURSOR"}


def _peek(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read(_PEEK_BYTES)


def _decode_lines(raw: bytes) -> list[str]:
    return _decode_text(raw).splitlines()


def _looks_like_qcloud_log(path: Path, raw: bytes) -> bool:
    normalized = path.as_posix().lower()
    name = path.name.lower()
    known_name = (
        name.startswith("ydservice.")
        or name.startswith("hids.log")
        or name.startswith("ydlive.log")
        or name.startswith("vul_scan.log")
        or name.startswith("baseline_scan.log")
        or name.startswith("ydflame.")
        or name.startswith("ydutils.log")
        or name.startswith("ydquarav2.log")
        or "ydeyes" in name
        or (name == "log.txt" and path.parent.name.lower() == "ydeyes")
    )
    lowered = raw.lower()
    return "/yunjing/" in normalized or known_name or any(marker in lowered for marker in _QCLOUD_PRODUCT_MARKERS)


def classify_file(path: Path) -> str | None:
    try:
        raw = _peek(path)
    except OSError:
        return None
    if not raw:
        return None

    # Windows Registry hive -- the literal 4-byte "regf" magic at the very
    # start of the file is a strictly more reliable signature than any of
    # the text-format heuristics below, and hive files are binary/NUL-heavy
    # (UTF-16 names, padding), so this must be checked before the
    # NUL-byte-density bailout further down would otherwise catch it first.
    if raw[:4] == b"regf":
        return KIND_REGISTRY_HIVE

    stripped = raw.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<Task"):
        if _TASK_XMLNS_RE.search(raw):
            return KIND_SCHEDULED_TASK
        return None

    if stripped.startswith(b"{"):
        first_line = stripped.splitlines()[0] if stripped.splitlines() else b""
        try:
            obj = json.loads(first_line)
        except (ValueError, UnicodeDecodeError):
            obj = None
        if isinstance(obj, dict) and _JOURNAL_EXPORT_MARKERS <= obj.keys():
            return KIND_JOURNAL_EXPORT

    # Binary-ish content (lots of NUL bytes) isn't one of our line-oriented formats.
    if raw.count(b"\x00") > len(raw) // 8:
        return None

    lines = _decode_lines(raw)
    fields_line: str | None = None
    software_line: str | None = None
    first_data_line: str | None = None
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("#Fields:"):
            fields_line = line[len("#Fields:") :].strip()
            continue
        if line.startswith("#Software:"):
            software_line = line[len("#Software:") :].strip()
            continue
        if _MYSQL_SLOW_MARKER_RE.match(line.encode("utf-8", errors="replace")):
            return KIND_MYSQL_SLOW
        if line.startswith("#"):
            continue
        if _MYSQL_GENERAL_HEADER_RE.match(line.encode("utf-8", errors="replace")):
            return KIND_MYSQL_GENERAL
        first_data_line = line
        break

    if software_line and "HTTP API" in software_line:
        return KIND_IIS_HTTPERR

    if software_line and "Exchange" in software_line:
        if fields_line:
            tokens = {t.strip() for t in fields_line.split(",")}
            if _MESSAGE_TRACKING_FIELDS.issubset(tokens):
                return KIND_EXCHANGE_MESSAGE_TRACKING
        return KIND_EXCHANGE_GENERIC

    if software_line and "Internet Information Services" in software_line:
        return KIND_IIS

    if fields_line:
        tokens = set(fields_line.split())
        if {"c-ip", "c-port", "s-reason"}.issubset(tokens):
            return KIND_IIS_HTTPERR
        if {"s-ip", "cs-method", "cs-uri-stem"}.issubset(tokens):
            return KIND_IIS
        comma_tokens = {t.strip() for t in fields_line.split(",")}
        if _MESSAGE_TRACKING_FIELDS.issubset(comma_tokens):
            return KIND_EXCHANGE_MESSAGE_TRACKING
        if "cs-uri-stem" in comma_tokens or "client-ip" in comma_tokens:
            return KIND_EXCHANGE_GENERIC

    if first_data_line:
        encoded = first_data_line.encode("utf-8", errors="replace")
        if _QCLOUD_YDSERVICE_RE.match(encoded):
            return KIND_QCLOUD_YDSERVICE
        if _QCLOUD_GO_RE.match(encoded) and _looks_like_qcloud_log(path, raw):
            return KIND_QCLOUD_GO
        if _QCLOUD_SCANNER_RE.match(encoded) and _looks_like_qcloud_log(path, raw):
            return KIND_QCLOUD_SCANNER
        if _QCLOUD_YDEYES_RE.match(encoded) and _looks_like_qcloud_log(path, raw):
            return KIND_QCLOUD_YDEYES
        if _NGINX_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_NGINX
        if _APACHE_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_APACHE
        if _TOMCAT_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_TOMCAT
        if _MYSQL_ERROR_NEW_RE.match(encoded) or _MYSQL_ERROR_OLD_RE.match(encoded):
            return KIND_MYSQL_ERROR
        if _POSTGRESQL_RE.match(encoded):
            return KIND_POSTGRESQL
        if _MSSQL_RE.match(encoded):
            return KIND_MSSQL
        if _ORACLE_ALERT_RE.match(encoded):
            return KIND_ORACLE_ALERT
        if _CLF_RE.match(encoded):
            return KIND_WEB_ACCESS
        if _AUDITD_RE.match(encoded):
            return KIND_AUDITD
        if _SYSLOG_5424_RE.match(encoded) or _SYSLOG_BSD_RE.match(encoded):
            return KIND_SYSLOG

    return None


def guess_web_log_type(path: Path) -> str:
    """Best-effort nginx/apache/tomcat label from path/filename context --
    Combined/Common Log Format is byte-identical across all three, so this
    is a heuristic, not a detection (see docs/known_limitations.md)."""
    haystack = str(path).lower()
    if "tomcat" in haystack or path.name.lower().startswith("localhost_access_log"):
        return "tomcat"
    if "nginx" in haystack:
        return "nginx"
    if "apache" in haystack or "httpd" in haystack:
        return "apache"
    return "web_access"
