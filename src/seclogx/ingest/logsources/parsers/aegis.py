"""Bounded readers for Alibaba Cloud Aegis agent text logs.

These are client diagnostics, not a declaration that a threat was detected.
The unlabelled numeric bracket is retained as ``context_id``: the evidence
does not establish that it is a process or thread identifier. Timestamps have
no timezone in these formats and remain naive. Client binaries and Python
representations embedded in messages are never executed or evaluated.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from ....textdecode import TextRecordTooLargeError, iter_text_lines
from ._stream import RowSink

MAX_AEGIS_RECORD_CHARS = 4 * 1024 * 1024
MAX_AEGIS_RECORD_LINES = 100_000
_LINE_ENDINGS = "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_TIME = r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
_LEVEL = r"(?P<severity>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)"
_CORE = re.compile(
    rf"^{_TIME}\s+\[{_LEVEL}\]\s*(?:\[(?P<context>\d+)\]\s*)?(?P<message>.*)$", re.IGNORECASE,
)
_CORE_CONTEXT_FIRST = re.compile(
    rf"^{_TIME}\s+\[(?P<context>\d+)\]\s*\[{_LEVEL}\]\s*(?P<message>.*)$", re.IGNORECASE,
)
_CORE_CONTEXT_ONLY = re.compile(
    rf"^{_TIME}\s+\[(?P<context>\d+)\]\s+(?P<message>.*)$"
)
_PYTHON = re.compile(
    rf"^{_TIME}\s+\[(?P<logger>[A-Za-z0-9_.-]+\.py)\]\s*\[{_LEVEL}\]\s*(?P<message>.*)$", re.IGNORECASE,
)
_TIMESTAMP_START = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:[ T]|$)")
_QUEUED = re.compile(r"^Add task:(?P<task>\S+)\s+id:(?P<id>\d+)\s+qlen:(?P<queue>\d+)\s*$")
_STARTED = re.compile(r"^Start Cron Task:\s*(?P<task>[^,\r\n]+),\s*taskId:\s*(?P<id>\d+)\s*$")
_COMPLETED = re.compile(r"^Task\s+(?P<id>\d+)\s+complete!\s+taken:\s*(?P<duration>\d+)ms\s*$")
_KNOWN_LOGGERS = frozenset({
    "alihips-config.py", "atd_lnx_reverse_shell.py", "linux-message-check.py",
    "linux-sysinfoext-check.py", "tcp-connect-check.py",
})
_PRODUCT_PATH_IN_TEXT = re.compile(
    r"(?:/usr/local/aegis/|(?:/|\\)(?:AliSecCheck(?:Tmp)?|AliHips|PythonLoader)(?:/|\\))",
    re.IGNORECASE,
)
_PRODUCT_BANNER = re.compile(r"={4,}Start AliSecCheck\s*:\s*[^\r\n]+={4,}")
_DATA_ROTATION = re.compile(r"data(?:\.\d+)+$")
_CLIENT_VERSION = re.compile(r"aegis_\d+(?:_\d+)+$")
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _path_metadata(path: Path) -> tuple[str, str, bool]:
    """Use component path segments, never the analyst's host/path spelling."""
    parts = str(path).replace("\\", "/").lower().split("/")
    component = "aegis"
    tail: list[str] = []
    for index, part in enumerate(parts):
        if part in {
            "aliseccheck", "alisecchecktmp", "alihips", "pythonloader",
            "aegis_client", "aegis_update",
        }:
            component = {
                "aliseccheck": "AliSecCheck", "alisecchecktmp": "AliSecCheckTmp",
                "alihips": "AliHips", "pythonloader": "PythonLoader",
                "aegis_client": "AegisClient", "aegis_update": "AegisUpdate",
            }[part]
            tail = parts[index + 1:]
    name = parts[-1] if parts else ""
    if name == "atd_lnx_reverse_shell.log" or name.startswith("atd_lnx_reverse_shell.log."):
        return "reverse_shell", component, True
    if component == "AliHips" and tail[:1] == ["log"] and len(tail) >= 2:
        return "hips", component, True
    if component in {"AliSecCheck", "AliSecCheckTmp"} and tail[:1] == ["data"]:
        if len(tail) >= 4 and tail[2] == "log":
            if tail[1] in {"detect", "rtap"}:
                return tail[1], component, True
            if component == "AliSecCheckTmp":
                return "security_check", component, True
        if name == "debug_hips.log" or name.startswith("debug_hips.log."):
            return "hips_debug", component, True
        if len(tail) == 2 and (
            re.search(r"\.log(?:\.\d+)?$", name) or _DATA_ROTATION.fullmatch(name)
        ):
            return "security_check", component, True
    if component == "PythonLoader" and tail[:1] == ["data"] and len(tail) == 2:
        if re.search(r"\.log(?:\.\d+)?$", name) or _DATA_ROTATION.fullmatch(name):
            return "python_loader", component, True
    if component == "AegisUpdate" and len(tail) == 2 and tail[0] == "data":
        if _DATA_ROTATION.fullmatch(name):
            return "update", component, True
    if component == "AegisClient" and len(tail) == 3 and _CLIENT_VERSION.fullmatch(tail[0]):
        if _DATA_ROTATION.fullmatch(name):
            if tail[1] == "data":
                return "client", component, True
            if tail[1] == "yun_dun_monitor_log":
                return "monitor", component, True
    return "agent", component, False


def _header(line: str) -> tuple[str, re.Match[str]] | None:
    body = line.rstrip(_LINE_ENDINGS)
    for kind, pattern in (
        ("aegis_python", _PYTHON), ("aegis_core", _CORE),
        ("aegis_core", _CORE_CONTEXT_FIRST), ("aegis_core", _CORE_CONTEXT_ONLY),
    ):
        match = pattern.match(body)
        if match is not None:
            return kind, match
    return None


def classify_aegis_prefix(path: Path, text: str, *, context_text: str | None = None) -> str | None:
    """Recognize a supplied decoded prefix without opening evidence again.

    A compatible envelope alone is too generic. It must be accompanied by a
    known component path, a known client logger, or an explicit product path
    in the same prefix. JSON configuration and unrecognised binary files do
    not become logs merely because of their names or containing directory.
    ``context_text`` lets classification test just the first record's shape
    while retaining product evidence from the whole bounded prefix.
    """
    _, _, known_path = _path_metadata(path)
    context = text if context_text is None else context_text
    product_path = _PRODUCT_PATH_IN_TEXT.search(context) is not None or _PRODUCT_BANNER.search(context) is not None
    for line in text.splitlines():
        parsed = _header(line)
        if parsed is None:
            continue
        kind, match = parsed
        known_logger = (match.groupdict().get("logger") or "").lower() in _KNOWN_LOGGERS
        if known_path or known_logger or product_path:
            return kind
    return None


def _event_fields(message: str, extra: dict) -> tuple[str | None, str | None, str | None, int | None]:
    first_line = message.splitlines()[0] if message else ""
    match = _QUEUED.fullmatch(first_line)
    if match:
        queue = match["queue"]
        extra["queue_length"] = int(queue) if len(queue) <= 18 else queue
        return "task_queued", match["task"], match["id"], None
    match = _STARTED.fullmatch(first_line)
    if match:
        return "task_started", match["task"].strip(), match["id"], None
    match = _COMPLETED.fullmatch(first_line)
    if match:
        text = match["duration"].lstrip("0") or "0"
        # Canonical BIGINT cannot represent arbitrary-length input integers.
        if len(text) <= 19 and int(text) <= 2**63 - 1:
            return "task_completed", None, match["id"], int(text)
        extra["duration_ms_text"] = match["duration"]
        return "task_completed", None, match["id"], None
    return None, None, None, None


def _json_payload(message: str) -> object | None:
    """Accept only a complete strict JSON object/array, optionally prefixed."""
    positions = [position for delimiter in "{[" if (position := message.find(delimiter)) >= 0]
    if not positions:
        return None
    candidate = message[min(positions):].strip()
    try:
        value = json.loads(
            candidate, parse_constant=_invalid_json_constant, parse_float=_finite_json_float,
        )
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _invalid_json_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds finite float range")
    return number


def _extra_json(message: str, extra: dict) -> str:
    """Optional payload enrichment must not make a readable record unwritable."""
    payload = _json_payload(message)
    if payload is not None:
        try:
            enriched = json.dumps({**extra, "json_payload": payload}, ensure_ascii=False)
        except RecursionError:
            # Wrapping a deeply nested payload can exceed the encoder's
            # depth even when the standalone JSON decoder accepted it.
            pass
        else:
            # JSON escapes may decode to lone surrogates in keys or values.
            # They cannot pass UTF-8/Arrow or portable JSON queries. The
            # original escaped text remains intact in message/raw_line.
            if _SURROGATE.search(enriched) is None:
                return enriched
    return json.dumps(extra, ensure_ascii=False)


def _parse_aegis_file(
    path: Path, host: str, *, emit: Callable[[dict], None] | None,
) -> tuple[list[dict], int, int]:
    rows = RowSink(emit)
    log_type, component, _ = _path_metadata(path)
    errors = 0
    parts: list[str] = []
    current: re.Match[str] | None = None
    current_time: str | None = None
    record_chars = 0

    def flush() -> None:
        nonlocal parts, current, current_time, record_chars
        if current is None:
            return
        raw = "".join(parts)
        message = raw[current.start("message"):]
        extra: dict = {"line_count": len(parts)}
        event_type, task_name, task_id, duration = _event_fields(message, extra)
        rows.append({
            "host": host, "log_type": log_type, "component": component,
            "logger": current.groupdict().get("logger"),
            "time_created": current_time,
            "severity": (current.groupdict().get("severity") or "").upper() or None,
            "context_id": current.groupdict().get("context"),
            "event_type": event_type, "task_name": task_name, "task_id": task_id,
            "duration_ms": duration, "message": message, "raw_line": raw,
            "extra": _extra_json(message, extra),
        })
        parts = []
        current = None
        current_time = None
        record_chars = 0

    def append(line: str) -> None:
        nonlocal record_chars
        size = len(line)
        if len(parts) >= MAX_AEGIS_RECORD_LINES or record_chars + size > MAX_AEGIS_RECORD_CHARS:
            raise TextRecordTooLargeError(
                f"Aegis event exceeds {MAX_AEGIS_RECORD_CHARS} characters or "
                f"{MAX_AEGIS_RECORD_LINES} physical lines: {path}"
            )
        parts.append(line)
        record_chars += size

    for line in iter_text_lines(
        path, keepends=True, max_line_chars=MAX_AEGIS_RECORD_CHARS,
    ):
        parsed = _header(line)
        if parsed is not None:
            flush()
            _, header = parsed
            try:
                timestamp = datetime.fromisoformat(header["timestamp"].replace(",", ".")).isoformat()
            except ValueError:
                errors += 1
                continue
            current = header
            current_time = timestamp
            append(line)
        elif _TIMESTAMP_START.match(line):
            # A damaged timestamp/header is a separate bad event, never part
            # of the previous event's apparently successful message.
            flush()
            errors += 1
        elif current is not None:
            append(line)
        elif line.strip():
            errors += 1
    flush()
    return rows.rows, rows.count, errors


def parse_aegis_core_file(
    path: Path, host: str, *, emit: Callable[[dict], None] | None = None,
) -> tuple[list[dict], int, int]:
    return _parse_aegis_file(Path(path), host, emit=emit)


def parse_aegis_python_file(
    path: Path, host: str, *, emit: Callable[[dict], None] | None = None,
) -> tuple[list[dict], int, int]:
    return _parse_aegis_file(Path(path), host, emit=emit)


def stream_aegis_core_file(path: Path, host: str, emit: Callable[[dict], None]) -> tuple[int, int]:
    _, ok, errors = _parse_aegis_file(Path(path), host, emit=emit)
    return ok, errors


def stream_aegis_python_file(path: Path, host: str, emit: Callable[[dict], None]) -> tuple[int, int]:
    _, ok, errors = _parse_aegis_file(Path(path), host, emit=emit)
    return ok, errors
