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

_MESSAGE_TRACKING_FIELDS = {"message-id", "recipient-address"}
# journald's "trusted", double-underscore-prefixed fields -- reliable,
# format-unique signal for `journalctl -o json` export lines (as opposed
# to any other line-delimited JSON log a source directory might contain).
_JOURNAL_EXPORT_MARKERS = {"__REALTIME_TIMESTAMP", "__CURSOR"}


def _peek(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read(_PEEK_BYTES)


def _decode_text(raw: bytes) -> str:
    """Best-effort bytes -> str for forensic log/artifact content of unknown
    origin. Tries progressively looser encodings -- UTF-8 (with BOM),
    UTF-16 (with BOM), then GB18030 (a strict superset of GBK/GB2312,
    covering Simplified/Traditional Chinese-locale logs and Windows
    artifacts) -- before falling back to Latin-1 with `errors="replace"`,
    which maps every byte 1:1 and therefore can never raise: even opaque
    binary data mixed into a text log becomes decodable (if not always
    meaningful) text rather than crashing the caller. GB18030 is a Python
    stdlib codec (`encodings.gb18030`), so this adds no new dependency."""
    for encoding in ("utf-8-sig", "utf-16", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _decode_lines(raw: bytes) -> list[str]:
    return _decode_text(raw).splitlines()


def classify_file(path: Path) -> str | None:
    try:
        raw = _peek(path)
    except OSError:
        return None
    if not raw:
        return None

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
        if line.startswith("#"):
            continue
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
        if _NGINX_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_NGINX
        if _APACHE_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_APACHE
        if _TOMCAT_ERROR_RE.match(encoded):
            return KIND_WEB_ERROR_TOMCAT
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
