"""Parse Linux Audit Framework (auditd) logs (`/var/log/audit/audit.log`)
into `auditd_logs` rows.

Each line is `type=RECORD_TYPE msg=audit(epoch.ms:serial): key=val ...`.
One row per *line*; a single real audit event is frequently several
related lines (e.g. SYSCALL + EXECVE + CWD + PATH, all sharing one
`audit_serial`) that this does not stitch back together -- correlate them
yourself with `WHERE audit_serial = ...` (see docs/known_limitations.md).
`syscall=` is kept as the raw number reported, not resolved to a name
(the syscall table is architecture-dependent).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..sniff import _decode_lines

_HEADER_RE = re.compile(r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s*(?P<rest>.*)$")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

_PROMOTED_FIELDS = {"syscall", "success", "exe", "comm", "uid", "auid", "pid", "ppid", "key"}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_auditd_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    """Returns (rows, ok_count, error_count). A line that doesn't match the
    `type=... msg=audit(epoch.ms:serial): ...` header is counted as an
    error, not silently dropped."""
    rows: list[dict] = []
    error_count = 0

    for line in _decode_lines(path.read_bytes()):
        if not line.strip():
            continue

        m = _HEADER_RE.match(line)
        if not m:
            error_count += 1
            continue

        try:
            epoch = int(m.group("epoch")) + int(m.group("ms")) / 1000
            time_created = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            time_created = None

        kv = {key: _unquote(value) for key, value in _KV_RE.findall(m.group("rest"))}

        row = {
            "host": host,
            "time_created": time_created,
            "audit_serial": int(m.group("serial")),
            "record_type": m.group("type"),
        }
        for field in _PROMOTED_FIELDS:
            row[field] = kv.pop(field, None)
        row["fields"] = json.dumps(kv) if kv else None
        rows.append(row)

    return rows, len(rows), error_count
