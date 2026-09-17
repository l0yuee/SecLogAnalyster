"""Parse Exchange's self-describing CSV logs (a shared convention across
Message Tracking, HttpProxy, ActiveSync/Eas, Ews, Imap, Pop, RpcHttp, and
other Exchange transport/connectivity logs: a `#Fields:` header line names
comma-delimited columns).

Message Tracking (mail flow: who sent what to whom, when, and what
happened to it) is the highest DFIR value and gets first-class columns.
Every other Exchange CSV log variant is routed into the `exchange_logs`
catchall table with all fields preserved verbatim in `fields` -- rather
than hand-modeling over a dozen schemas, none of which are silently
dropped just because they aren't message tracking.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import Callable, Iterator

from ....textdecode import MAX_TEXT_RECORD_CHARS, TextRecordTooLargeError, iter_text_lines
from ._stream import RowSink

_MESSAGE_TRACKING_FIELD_MAP = {
    "date-time": "time_created",
    "client-ip": "client_ip",
    "client-hostname": "client_hostname",
    "server-ip": "server_ip",
    "server-hostname": "server_hostname",
    "source-context": "source_context",
    "connector-id": "connector_id",
    "source": "source",
    "event-id": "event_id",
    "internal-message-id": "internal_message_id",
    "message-id": "message_id",
    "network-message-id": "network_message_id",
    "recipient-address": "recipient_address",
    "recipient-status": "recipient_status",
    "total-bytes": "total_bytes",
    "recipient-count": "recipient_count",
    "related-recipient-address": "related_recipient_address",
    "reference": "reference",
    "message-subject": "message_subject",
    "sender-address": "sender_address",
    "return-path": "return_path",
    "directionality": "directionality",
    "tenant-id": "tenant_id",
}
_MT_INT_FIELDS = {"total_bytes", "recipient_count"}


def _parse_datetime(raw: str) -> str | None:
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return None


def _record_lines(first: str, lines: Iterator[str], path: Path) -> Iterator[str]:
    """Feed exactly as many physical lines as csv.reader requests for a row.

    Header-like text inside a quoted field is data, and original newline
    characters are preserved. Enforce a limit on the whole logical record,
    including when a malformed quoted field would otherwise consume EOF.
    """
    length = 0
    for line in chain((first,), lines):
        length += len(line)
        if length > MAX_TEXT_RECORD_CHARS:
            raise TextRecordTooLargeError(
                f"Exchange CSV record exceeds {MAX_TEXT_RECORD_CHARS} characters: {path}"
            )
        yield line


def parse_exchange_csv(
    path: Path, host: str, subkind: str, *, emit: Callable[[dict], None] | None = None
) -> tuple[str, list[dict], int, int]:
    """Returns (table, rows, ok_count, error_count) where table is
    'exchange_message_tracking' or 'exchange_logs'."""
    fields: list[str] | None = None
    log_type_header: str | None = None
    rows = RowSink(emit)
    error_count = 0
    table = "exchange_message_tracking" if subkind == "exchange_message_tracking" else "exchange_logs"

    lines = iter_text_lines(path, keepends=True)
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("#Fields:"):
            fields = [t.strip() for t in line[len("#Fields:"):].split(",")]
            continue
        if line.startswith("#Log-type:"):
            log_type_header = line[len("#Log-type:"):].strip()
            continue
        if line.startswith("#"):
            continue
        if not fields:
            error_count += 1
            continue
        try:
            values = next(csv.reader(_record_lines(line, lines, path), strict=True))
        except csv.Error as exc:
            if "field larger than field limit" in str(exc):
                raise TextRecordTooLargeError(
                    f"Exchange CSV field exceeds {csv.field_size_limit()} characters: {path}"
                ) from exc
            error_count += 1
            continue
        if len(values) != len(fields):
            error_count += 1
            continue
        rec = dict(zip(fields, values))

        if table == "exchange_message_tracking":
            rows.append(_normalize_message_tracking(rec, host))
        else:
            time_created = _parse_datetime(rec.get("date-time") or rec.get("DateTime") or "")
            rows.append(
                {
                    "host": host,
                    "log_type": log_type_header or "exchange_generic",
                    "time_created": time_created,
                    "fields": json.dumps(rec),
                }
            )

    return table if fields else "exchange_logs", rows.rows, rows.count, error_count


def _normalize_message_tracking(rec: dict, host: str) -> dict:
    row: dict = {"host": host}
    extra = {}
    for src_field, value in rec.items():
        value = value if value != "" else None
        if src_field in _MESSAGE_TRACKING_FIELD_MAP:
            dest = _MESSAGE_TRACKING_FIELD_MAP[src_field]
            if value is not None and dest in _MT_INT_FIELDS:
                try:
                    value = int(value)
                except ValueError:
                    value = None
            if dest == "time_created":
                value = _parse_datetime(value) if value else None
            row[dest] = value
        else:
            extra[src_field] = value
    row["extra"] = json.dumps(extra) if extra else None
    for dest in _MESSAGE_TRACKING_FIELD_MAP.values():
        row.setdefault(dest, None)
    return row
