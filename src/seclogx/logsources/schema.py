"""Canonical schemas for the non-EVTX log families: on-disk Scheduled Task
definitions, IIS/nginx/Apache/Tomcat HTTP access logs, and Exchange's
self-describing CSV logs.

Each of these is fundamentally a different shape than a Windows Event Log
record (no channel/event_id/event_data triad), so each gets its own
Parquet table under `lake/<table>/` rather than being crammed into
`events`. `query.CaseDB` discovers these tables automatically (any
subdirectory of `lake/` with Parquet files becomes a view named after the
subdirectory) -- no per-table wiring needed there.

Columns not covered by a table's fixed set are never dropped: each table
carries a JSON catchall column (`extra` / `actions` / `triggers` / `fields`)
so an unusual field, trigger type, or Exchange log variant is still fully
queryable, just not promoted to a first-class column. Same "never silently
drop data" principle as the EVTX pipeline's `event_data` column.

As with `schema.py`, JSON/text catchall columns are explicitly cast to
VARCHAR in CAST_SQL so an all-NULL batch (e.g. a purely IIS ingest batch
with no `extra` fields) doesn't let DuckDB infer a different physical
Parquet column type than a later batch with real content, which would
break `union_by_name` reads across the lake (see docs/known_limitations.md
for the original discovery of this failure mode).
"""

from __future__ import annotations

SCHEMA_VERSION = 1

# (column_name, duckdb_type)
WEB_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("log_type", "VARCHAR"),  # 'iis' | 'nginx' | 'apache' | 'tomcat' | 'web_access' | 'exchange_http_proxy'
    ("time_created", "TIMESTAMP"),
    ("client_ip", "VARCHAR"),
    ("server_ip", "VARCHAR"),
    ("server_port", "VARCHAR"),
    ("method", "VARCHAR"),
    ("uri_stem", "VARCHAR"),
    ("uri_query", "VARCHAR"),
    ("protocol_version", "VARCHAR"),
    ("status", "INTEGER"),
    ("substatus", "INTEGER"),  # IIS-only (sc-substatus), NULL elsewhere
    ("win32_status", "INTEGER"),  # IIS-only (sc-win32-status), NULL elsewhere
    ("bytes_sent", "BIGINT"),
    ("bytes_received", "BIGINT"),  # IIS-only (cs-bytes), NULL elsewhere
    ("time_taken_ms", "BIGINT"),
    ("username", "VARCHAR"),
    ("user_agent", "VARCHAR"),
    ("referer", "VARCHAR"),
    ("extra", "JSON"),  # catchall for W3C fields beyond the fixed set above
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
WEB_LOGS_PARTITION_COLUMNS = ["host", "log_type"]

SCHEDULED_TASKS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("task_path", "VARCHAR"),  # e.g. \Microsoft\Windows\...\TaskName, derived from the Tasks folder layout
    ("task_name", "VARCHAR"),  # leaf name (source file basename -- task files have no extension on disk)
    ("author", "VARCHAR"),
    ("description", "VARCHAR"),
    ("date_registered", "TIMESTAMP"),
    ("enabled", "BOOLEAN"),
    ("hidden", "BOOLEAN"),
    ("principal_user_id", "VARCHAR"),
    ("principal_run_level", "VARCHAR"),
    ("principal_logon_type", "VARCHAR"),
    ("actions", "JSON"),  # list of {type, ...} -- Exec/ComHandler/SendEmail/ShowMessage, captured generically
    ("triggers", "JSON"),  # list of {type, ...} -- TimeTrigger/LogonTrigger/BootTrigger/... captured generically
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
SCHEDULED_TASKS_PARTITION_COLUMNS = ["host"]

EXCHANGE_MESSAGE_TRACKING_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("time_created", "TIMESTAMP"),
    ("client_ip", "VARCHAR"),
    ("client_hostname", "VARCHAR"),
    ("server_ip", "VARCHAR"),
    ("server_hostname", "VARCHAR"),
    ("source_context", "VARCHAR"),
    ("connector_id", "VARCHAR"),
    ("source", "VARCHAR"),
    ("event_id", "VARCHAR"),  # Exchange's own transport event id (SEND/RECEIVE/...), not a Windows Event ID
    ("internal_message_id", "VARCHAR"),
    ("message_id", "VARCHAR"),  # RFC 5322 Message-ID header
    ("network_message_id", "VARCHAR"),
    ("recipient_address", "VARCHAR"),  # may be ';'-separated for multi-recipient rows, kept raw (see known_limitations)
    ("recipient_status", "VARCHAR"),
    ("total_bytes", "BIGINT"),
    ("recipient_count", "INTEGER"),
    ("related_recipient_address", "VARCHAR"),
    ("reference", "VARCHAR"),
    ("message_subject", "VARCHAR"),
    ("sender_address", "VARCHAR"),
    ("return_path", "VARCHAR"),
    ("directionality", "VARCHAR"),
    ("tenant_id", "VARCHAR"),
    ("extra", "JSON"),  # catchall: message-info, original-client-ip, custom-data, schema-version, ...
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
EXCHANGE_MESSAGE_TRACKING_PARTITION_COLUMNS = ["host"]

# Catchall for Exchange CSV log types other than message tracking (HttpProxy,
# ActiveSync/Eas, Ews, Imap, Pop, RpcHttp, ...). Exchange ships over a dozen
# such self-describing "#Fields:"-headered log formats; rather than
# hand-modeling each one, every field is preserved verbatim in `fields` --
# still fully queryable via `fields ->> 'field-name'` -- so no Exchange log
# variant is silently dropped just because it isn't message tracking.
EXCHANGE_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("log_type", "VARCHAR"),  # from the '#Log-type:' header line, e.g. 'HttpProxy', or 'exchange_generic'
    ("time_created", "TIMESTAMP"),
    ("fields", "JSON"),  # the full self-described CSV row, keyed by its '#Fields:' header
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
EXCHANGE_LOGS_PARTITION_COLUMNS = ["host", "log_type"]

TABLES: dict[str, dict] = {
    "web_logs": {"columns": WEB_LOGS_COLUMNS, "partition_by": WEB_LOGS_PARTITION_COLUMNS},
    "scheduled_tasks": {"columns": SCHEDULED_TASKS_COLUMNS, "partition_by": SCHEDULED_TASKS_PARTITION_COLUMNS},
    "exchange_message_tracking": {
        "columns": EXCHANGE_MESSAGE_TRACKING_COLUMNS,
        "partition_by": EXCHANGE_MESSAGE_TRACKING_PARTITION_COLUMNS,
    },
    "exchange_logs": {"columns": EXCHANGE_LOGS_COLUMNS, "partition_by": EXCHANGE_LOGS_PARTITION_COLUMNS},
}

# Columns holding JSON-serialized text (lists/dicts) or otherwise needing an
# explicit VARCHAR cast rather than TRY_CAST to their declared type, to
# guarantee stable physical Parquet typing across ingest batches.
_TEXT_CAST_COLUMNS = {"extra", "actions", "triggers", "fields"}


def cast_sql_for(table: str) -> dict[str, str]:
    """Per-column SQL casting a value already present in a batch DataFrame
    under `raw`. Callers add `CAST(NULL AS <type>) AS <col>` themselves for
    columns absent from a given batch."""
    out = {}
    for col, duckdb_type in TABLES[table]["columns"]:
        if col in _TEXT_CAST_COLUMNS or duckdb_type in ("VARCHAR", "JSON"):
            out[col] = f"CAST(raw.{col} AS VARCHAR)"
        else:
            out[col] = f"TRY_CAST(raw.{col} AS {duckdb_type})"
    return out
