"""Canonical schemas for the non-EVTX log families: on-disk Scheduled Task
definitions, IIS/nginx/Apache/Tomcat HTTP access AND error logs, and
Exchange's self-describing CSV logs.

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

# The other major web-application log category besides access logs: error/
# diagnostic logs. Structurally unlike access logs (no request/response
# shape in the nginx/Apache/Tomcat case, just severity + free-text message),
# so it's a separate table rather than forced into WEB_LOGS_COLUMNS.
WEB_ERROR_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("log_type", "VARCHAR"),  # 'nginx' | 'apache' | 'tomcat' | 'iis_httperr'
    ("time_created", "TIMESTAMP"),
    ("severity", "VARCHAR"),  # nginx: emerg/alert/crit/error/warn/notice/info/debug; Tomcat: SEVERE/WARNING/...
    ("pid_or_thread", "VARCHAR"),  # nginx pid#tid; Apache pid[:tid]; Tomcat thread name
    ("client_ip", "VARCHAR"),
    ("client_port", "VARCHAR"),
    ("server_ip", "VARCHAR"),  # IIS HTTPERR only (s-ip), NULL elsewhere
    ("server_port", "VARCHAR"),  # IIS HTTPERR only (s-port), NULL elsewhere
    ("protocol_version", "VARCHAR"),  # IIS HTTPERR only (cs-version), NULL elsewhere
    ("method", "VARCHAR"),  # IIS HTTPERR only (cs-method), NULL elsewhere
    ("uri", "VARCHAR"),  # IIS HTTPERR only (cs-uri), NULL elsewhere
    ("status", "INTEGER"),  # IIS HTTPERR only (sc-status), NULL elsewhere
    ("logger", "VARCHAR"),  # Tomcat only (java.util.logging logger name), NULL elsewhere
    ("message", "VARCHAR"),  # nginx/Apache/Tomcat free-text message; IIS HTTPERR's s-reason
    ("extra", "JSON"),  # catchall (e.g. IIS HTTPERR s-siteid/s-queue)
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
WEB_ERROR_LOGS_PARTITION_COLUMNS = ["host", "log_type"]

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
    ("action_command", "VARCHAR"),  # first Exec action's Command, if any -- derived from `actions` for direct filtering
    ("action_arguments", "VARCHAR"),  # first Exec action's Arguments, if any
    ("action_working_directory", "VARCHAR"),  # first Exec action's WorkingDirectory, if any
    ("action_types", "VARCHAR"),  # comma-joined action element types, e.g. 'Exec' or 'Exec,ComHandler'
    ("trigger_types", "VARCHAR"),  # comma-joined trigger element types, e.g. 'TimeTrigger,LogonTrigger'
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

# Generic syslog (BSD/RFC-3164, with or without a <PRI> prefix, and RFC
# 5424) -- covers /var/log/syslog, messages, kern.log, daemon.log,
# mail.log, cron.log, auth.log/secure, and anything else rsyslog/syslog-ng
# writes in one of these two wire formats. auth.log is *not* a separate
# sniff kind or table: it's syslog format like everything else, just with
# recognizable program names/message shapes in it -- see
# Case.auth_events() / ingest/logsources/parsers/syslog.py:extract_auth_events
# for the derived, curated view over this table.
SYSLOG_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("time_created", "TIMESTAMP"),
    ("hostname", "VARCHAR"),  # syslog-reported hostname -- may differ from analyst-assigned host
    ("facility", "VARCHAR"),  # kern/user/mail/daemon/auth/syslog/cron/authpriv/local0-7/... ; NULL if no <PRI>
    ("severity", "VARCHAR"),  # emerg/alert/crit/err/warning/notice/info/debug ; NULL if no <PRI>
    ("app_name", "VARCHAR"),  # program/tag, e.g. sshd, CRON, sudo, kernel
    ("proc_id", "VARCHAR"),  # pid in brackets (BSD) or PROCID (RFC5424)
    ("msg_id", "VARCHAR"),  # RFC5424 MSGID only, NULL for BSD-format lines
    ("message", "VARCHAR"),  # free-text message body
    ("structured_data", "JSON"),  # RFC5424 SD-ELEMENTs, NULL for BSD-format lines or SD-DATA '-'
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
SYSLOG_PARTITION_COLUMNS = ["host"]

# Linux Audit Framework (auditd) -- /var/log/audit/audit.log,
# `type=X msg=audit(epoch.ms:serial): key=val ...` format. One row per
# *line*; a real audit event is often several related lines (SYSCALL +
# EXECVE + CWD + PATH + ...) sharing one audit_serial, which this does not
# stitch back together -- filter/join on audit_serial yourself (see
# docs/known_limitations.md).
AUDITD_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("time_created", "TIMESTAMP"),
    ("audit_serial", "BIGINT"),  # the audit(epoch:SERIAL) id -- ties related lines together
    ("record_type", "VARCHAR"),  # SYSCALL / EXECVE / CWD / PATH / USER_AUTH / CRED_ACQ / ...
    ("syscall", "VARCHAR"),  # raw syscall= number as text -- not resolved to a name (arch-dependent)
    ("success", "VARCHAR"),  # 'yes'/'no' as reported ; not every record_type has one
    ("exe", "VARCHAR"),
    ("comm", "VARCHAR"),
    ("uid", "VARCHAR"),
    ("auid", "VARCHAR"),  # loginuid -- the original authenticated user, survives su/sudo
    ("pid", "VARCHAR"),
    ("ppid", "VARCHAR"),
    ("key", "VARCHAR"),  # the triggering audit rule's -k tag, when set
    ("fields", "JSON"),  # every key=value pair on the line not promoted above, verbatim
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
AUDITD_LOGS_PARTITION_COLUMNS = ["host", "record_type"]

# systemd journal export format (`journalctl -o json`), one JSON object per
# line -- the standard log source on modern systemd distros. Not the same
# as the binary journal itself (/var/journal/**), which isn't portable
# across systems and isn't parsed here.
JOURNAL_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("time_created", "TIMESTAMP"),  # from __REALTIME_TIMESTAMP (microseconds since epoch)
    ("hostname", "VARCHAR"),  # _HOSTNAME
    ("unit", "VARCHAR"),  # _SYSTEMD_UNIT
    ("syslog_identifier", "VARCHAR"),  # SYSLOG_IDENTIFIER
    ("priority", "VARCHAR"),  # PRIORITY (0-7, syslog severity scale)
    ("pid", "VARCHAR"),  # _PID
    ("uid", "VARCHAR"),  # _UID
    ("comm", "VARCHAR"),  # _COMM
    ("exe", "VARCHAR"),  # _EXE
    ("message", "VARCHAR"),  # MESSAGE
    ("fields", "JSON"),  # every other journal field verbatim (_TRANSPORT, _BOOT_ID, custom fields, ...)
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
JOURNAL_LOGS_PARTITION_COLUMNS = ["host"]

# Database server logs -- MySQL/MariaDB (error, general query, and slow
# query logs), PostgreSQL (stderr-format log), MSSQL (ERRORLOG), and
# Oracle (alert log). Each engine/sub-format is unambiguous from its own
# content but structurally different from the others (free-text error
# lines vs. tab-separated query lines vs. multi-line slow-query blocks vs.
# timestamp-delimited alert blocks), so -- same as WEB_ERROR_LOGS_COLUMNS
# unifying nginx/Apache/Tomcat/IIS HTTPERR -- they land in one table with
# a `log_type` discriminator rather than one table per engine. See
# docs/known_limitations.md for the content-sniffing caveats specific to
# each sub-format (PostgreSQL log_line_prefix, MySQL general/slow log
# marker-line dependence, Oracle alert log banner-before-timestamp).
DB_LOGS_COLUMNS: list[tuple[str, str]] = [
    ("host", "VARCHAR"),
    ("log_type", "VARCHAR"),  # 'mysql_error' | 'mysql_general' | 'mysql_slow' | 'postgresql' | 'mssql' | 'oracle'
    ("time_created", "TIMESTAMP"),
    ("severity", "VARCHAR"),  # mysql_error: Note/Warning/ERROR/System; postgresql: LOG/ERROR/WARNING/...; NULL elsewhere
    ("component", "VARCHAR"),  # mysql_error subsystem tag; mssql spid/component token; mysql_general Command; NULL elsewhere
    ("error_code", "VARCHAR"),  # mysql_error 'MY-XXXXX'; oracle 'ORA-#####' extracted from message; NULL elsewhere
    ("thread_id", "VARCHAR"),  # mysql thread/connection Id; postgresql pid; mssql spid digits; NULL for oracle
    ("user_name", "VARCHAR"),  # mysql_slow User@Host user; postgresql user; NULL elsewhere
    ("database_name", "VARCHAR"),  # postgresql database; NULL elsewhere
    ("client_address", "VARCHAR"),  # mysql_slow User@Host host part; NULL elsewhere
    ("query_time_sec", "DOUBLE"),  # mysql_slow Query_time; NULL elsewhere
    ("rows_examined", "BIGINT"),  # mysql_slow Rows_examined; NULL elsewhere
    ("message", "VARCHAR"),  # free-text message / SQL statement text / general-log argument
    ("extra", "JSON"),  # catchall (e.g. mysql_slow's lock_time/rows_sent)
    ("source_path", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("file_sha256", "VARCHAR"),
    ("ingest_batch_id", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    ("schema_version", "UTINYINT"),
]
DB_LOGS_PARTITION_COLUMNS = ["host", "log_type"]

TABLES: dict[str, dict] = {
    "web_logs": {"columns": WEB_LOGS_COLUMNS, "partition_by": WEB_LOGS_PARTITION_COLUMNS},
    "web_error_logs": {"columns": WEB_ERROR_LOGS_COLUMNS, "partition_by": WEB_ERROR_LOGS_PARTITION_COLUMNS},
    "scheduled_tasks": {"columns": SCHEDULED_TASKS_COLUMNS, "partition_by": SCHEDULED_TASKS_PARTITION_COLUMNS},
    "exchange_message_tracking": {
        "columns": EXCHANGE_MESSAGE_TRACKING_COLUMNS,
        "partition_by": EXCHANGE_MESSAGE_TRACKING_PARTITION_COLUMNS,
    },
    "exchange_logs": {"columns": EXCHANGE_LOGS_COLUMNS, "partition_by": EXCHANGE_LOGS_PARTITION_COLUMNS},
    "syslog": {"columns": SYSLOG_COLUMNS, "partition_by": SYSLOG_PARTITION_COLUMNS},
    "auditd_logs": {"columns": AUDITD_LOGS_COLUMNS, "partition_by": AUDITD_LOGS_PARTITION_COLUMNS},
    "journal_logs": {"columns": JOURNAL_LOGS_COLUMNS, "partition_by": JOURNAL_LOGS_PARTITION_COLUMNS},
    "db_logs": {"columns": DB_LOGS_COLUMNS, "partition_by": DB_LOGS_PARTITION_COLUMNS},
}

# Columns holding JSON-serialized text (lists/dicts) or otherwise needing an
# explicit VARCHAR cast rather than TRY_CAST to their declared type, to
# guarantee stable physical Parquet typing across ingest batches.
_TEXT_CAST_COLUMNS = {"extra", "actions", "triggers", "fields", "structured_data"}


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
