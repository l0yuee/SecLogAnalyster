# Normalized schemas

Column reference for every table a case can have. This file covers two
sources: the Windows Event Log schema below (`src/seclogx/schema.py`),
and every other log family's schema further down (`## Non-EVTX log
tables`, from `src/seclogx/ingest/logsources/schema.py`) -- `events`,
`web_logs`, `web_error_logs`, `scheduled_tasks`,
`exchange_message_tracking`, `exchange_logs`, `syslog`, `auditd_logs`,
`journal_logs`, `db_logs`. See "Quick reference: analyzing each log type" in
[`docs/guides/02_log_types_and_schema.md`](guides/02_log_types_and_schema.md)
for how to actually query each one, and `docs/architecture.md` for how
they're ingested.

## `events` (Windows Event Log)

Schema version: `1` (see `schema_version` column). Generated from `src/seclogx/schema.py` -- regenerate this file if that module changes.

Parquet partition columns: `host, channel`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `channel` | `VARCHAR` | EVTX channel, e.g. 'Security', 'Microsoft-Windows-Sysmon/Operational' (partition key) |
| `provider_name` | `VARCHAR` | Event provider name |
| `provider_guid` | `VARCHAR` | Event provider GUID, nullable |
| `event_id` | `INTEGER` | Windows Event ID |
| `version` | `UTINYINT` | Event ID version, nullable |
| `time_created` | `TIMESTAMP` | Event timestamp (UTC, from System/TimeCreated) |
| `computer` | `VARCHAR` | Hostname embedded in the log itself (may differ from `host`) |
| `record_id` | `BIGINT` | EVTX EventRecordID (unique within source file) |
| `process_id` | `UINTEGER` | Generating process ID, nullable |
| `thread_id` | `UINTEGER` | Generating thread ID, nullable |
| `user_sid` | `VARCHAR` | Security/@UserID SID, nullable |
| `level` | `UTINYINT` | Raw level code |
| `level_name` | `VARCHAR` | Critical/Error/Warning/Information/Verbose, derived |
| `task` | `UINTEGER` | Task code, nullable |
| `opcode` | `UTINYINT` | Opcode, nullable |
| `keywords` | `VARCHAR` | Raw keywords hex bitmask (not decoded in v1) |
| `activity_id` | `VARCHAR` | Correlation/@ActivityID, nullable |
| `related_activity_id` | `VARCHAR` | Correlation/@RelatedActivityID, nullable |
| `event_data` | `JSON` | Flattened EventData (or UserData fallback) Name->Value payload |
| `raw_xml` | `VARCHAR` | Full raw record XML; only populated with --keep-raw |
| `source_path` | `VARCHAR` | Full acquisition path of the source .evtx file |
| `source_file` | `VARCHAR` | Basename of the source .evtx file |
| `file_sha256` | `VARCHAR` | SHA-256 of the source .evtx file (chain of custody) |
| `ingest_batch_id` | `VARCHAR` | UUID of the ingest run that produced this row |
| `ingested_at` | `TIMESTAMP` | Load time |
| `schema_version` | `UTINYINT` | Normalized schema version |

### `event_data`

Holds the provider-specific `EventData` (or `UserData` fallback) Name->Value payload as JSON text. Query individual fields with DuckDB's `->>` operator, e.g.:

```sql
SELECT event_data ->> 'Image', event_data ->> 'CommandLine'
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
```

See `docs/known_limitations.md` for the cases where `event_data` isn't a flat Name->Value dict (legacy unnamed `Data` arrays, `UserData` nesting).

---

**The remaining tables** (generated from / kept in sync with
`src/seclogx/ingest/logsources/schema.py`) are the non-EVTX log families. Each
lives under its own `lake/<table>/` subdirectory and is registered as a
view of the same name by `CaseDB` -- only present if the case has
ingested that log family (check `Case.table_counts()` / `seclogx sources`).
See `docs/architecture.md` for how these are ingested.

## `web_logs`

IIS, nginx, Apache, and Tomcat HTTP access logs, unified into one table so
cross-server correlation (e.g. a reverse-proxy hit followed by a backend
IIS hit for the same request) doesn't require a join across tables.
Partition columns: `host, log_type`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `log_type` | `VARCHAR` | `iis` \| `nginx` \| `apache` \| `tomcat` \| `web_access` \| `exchange_http_proxy` (partition key) |
| `time_created` | `TIMESTAMP` | Request timestamp |
| `client_ip` | `VARCHAR` | Requesting client IP |
| `server_ip` | `VARCHAR` | IIS-only (`s-ip`), NULL elsewhere |
| `server_port` | `VARCHAR` | IIS-only (`s-port`), NULL elsewhere |
| `method` | `VARCHAR` | HTTP method |
| `uri_stem` | `VARCHAR` | Request path, query string excluded |
| `uri_query` | `VARCHAR` | Query string, NULL if none |
| `protocol_version` | `VARCHAR` | e.g. `HTTP/1.1` |
| `status` | `INTEGER` | HTTP status code |
| `substatus` | `INTEGER` | IIS-only (`sc-substatus`), NULL elsewhere |
| `win32_status` | `INTEGER` | IIS-only (`sc-win32-status`), NULL elsewhere |
| `bytes_sent` | `BIGINT` | Response bytes |
| `bytes_received` | `BIGINT` | IIS-only (`cs-bytes`), NULL elsewhere |
| `time_taken_ms` | `BIGINT` | IIS-only (`time-taken`), NULL elsewhere |
| `username` | `VARCHAR` | Authenticated username, if any |
| `user_agent` | `VARCHAR` | Client User-Agent |
| `referer` | `VARCHAR` | Referer header |
| `extra` | `JSON` | Any W3C field beyond the fixed set above (IIS logs are admin-customizable) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance, same convention as `events` |

This covers the **access log** category. See `web_error_logs` below for
the other major web-application log category, **error/diagnostic logs**.

## `web_error_logs`

The error/diagnostic log category of nginx, Apache, Tomcat, and IIS --
structurally different from access logs (no request/response shape for
the first three, just severity + free-text message), so it's a separate
table. Unlike access-log format, error-log format is engine-specific and
unambiguous, so `log_type` here is a real detection, not a path/filename
heuristic. Partition columns: `host, log_type`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `log_type` | `VARCHAR` | `nginx` \| `apache` \| `tomcat` \| `iis_httperr` (partition key) |
| `time_created` | `TIMESTAMP` | Log entry timestamp |
| `severity` | `VARCHAR` | nginx: `emerg`/`alert`/`crit`/`error`/`warn`/`notice`/`info`/`debug`; Tomcat: `SEVERE`/`WARNING`/`INFO`/... ; NULL for IIS HTTPERR |
| `pid_or_thread` | `VARCHAR` | nginx `pid#tid`; Apache `pid`; Tomcat thread name; NULL for IIS HTTPERR |
| `client_ip` / `client_port` | `VARCHAR` | Client endpoint, where the format carries one |
| `server_ip` / `server_port` | `VARCHAR` | IIS HTTPERR-only (`s-ip`/`s-port`), NULL elsewhere |
| `protocol_version` | `VARCHAR` | IIS HTTPERR-only (`cs-version`), NULL elsewhere |
| `method` | `VARCHAR` | IIS HTTPERR-only (`cs-method`), NULL elsewhere |
| `uri` | `VARCHAR` | IIS HTTPERR-only (`cs-uri`), NULL elsewhere |
| `status` | `INTEGER` | IIS HTTPERR-only (`sc-status`), NULL elsewhere |
| `logger` | `VARCHAR` | Tomcat-only (java.util.logging logger name), NULL elsewhere |
| `message` | `VARCHAR` | nginx/Apache free text; Tomcat's message plus any attached stack trace lines; IIS HTTPERR's `s-reason` |
| `extra` | `JSON` | Catchall (e.g. IIS HTTPERR's `s-siteid`/`s-queue`) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `scheduled_tasks`

On-disk Task Scheduler task definitions (`C:\Windows\System32\Tasks\**`) --
a persistence artifact, distinct from the Task Scheduler *event log*
channel (already covered generically by `events`, since v1 ingests every
EVTX channel). Partition column: `host`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `task_path` | `VARCHAR` | Task Scheduler folder path, derived from the acquisition's `Tasks\` layout |
| `task_name` | `VARCHAR` | Source file basename (task files have no extension on a live system) |
| `author` | `VARCHAR` | `RegistrationInfo/Author` |
| `description` | `VARCHAR` | `RegistrationInfo/Description` |
| `date_registered` | `TIMESTAMP` | `RegistrationInfo/Date` |
| `enabled` | `BOOLEAN` | `Settings/Enabled` |
| `hidden` | `BOOLEAN` | `Settings/Hidden` |
| `principal_user_id` | `VARCHAR` | Principal the task runs as |
| `principal_run_level` | `VARCHAR` | e.g. `HighestAvailable` |
| `principal_logon_type` | `VARCHAR` | e.g. `InteractiveToken`, `S4U` |
| `action_command` | `VARCHAR` | First `Exec` action's `Command`, if any -- derived from `actions` for direct filtering without parsing JSON |
| `action_arguments` | `VARCHAR` | First `Exec` action's `Arguments`, if any |
| `action_working_directory` | `VARCHAR` | First `Exec` action's `WorkingDirectory`, if any |
| `action_types` | `VARCHAR` | Comma-joined action element types present, e.g. `Exec` or `Exec,ComHandler` |
| `trigger_types` | `VARCHAR` | Comma-joined trigger element types present, e.g. `TimeTrigger,LogonTrigger` |
| `actions` | `JSON` | List of `{type, ...}` -- every action element captured generically (Exec/ComHandler/SendEmail/ShowMessage) |
| `triggers` | `JSON` | List of `{type, ...}` -- every trigger element captured generically (TimeTrigger/LogonTrigger/BootTrigger/...) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

`Case.scheduled_tasks()` returns this table in full, for open-ended
analysis (filter/group on `action_command`, `task_path`, etc. directly).
`Case.suspicious_tasks()` / `seclogx tasks <case> --suspicious` layer a
lightweight heuristic on top (action path under Temp/AppData/Public, a
LOLBin-like command, a hidden/unauthored task, or a known Microsoft task
path whose action doesn't match its expected executable location --
see `data/scheduled_tasks/known_microsoft_tasks.json` and
`docs/known_limitations.md`) -- not a Sigma rule, since Sigma has no
logsource category for on-disk task definitions. The returned rows carry
a `suspicion_reasons` column (list of which heuristic(s) matched) rather
than a bare filter.

## `exchange_message_tracking`

Exchange mail flow logs (who sent what to whom, when, and what happened
to it) -- the highest DFIR value of Exchange's many log types. Partition
column: `host`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `time_created` | `TIMESTAMP` | `date-time` |
| `client_ip`, `client_hostname`, `server_ip`, `server_hostname` | `VARCHAR` | Transport hop endpoints |
| `source_context`, `connector_id`, `source` | `VARCHAR` | Transport routing context |
| `event_id` | `VARCHAR` | Exchange's own transport event id (e.g. `RECEIVE`, `SEND`) -- **not** a Windows Event ID |
| `internal_message_id`, `message_id`, `network_message_id` | `VARCHAR` | Message identifiers (`message_id` is the RFC 5322 Message-ID header) |
| `recipient_address` | `VARCHAR` | May be `;`-separated for multi-recipient rows (see known_limitations) |
| `recipient_status` | `VARCHAR` | Delivery outcome |
| `total_bytes` | `BIGINT` | Message size |
| `recipient_count` | `INTEGER` | |
| `related_recipient_address`, `reference` | `VARCHAR` | |
| `message_subject`, `sender_address`, `return_path` | `VARCHAR` | |
| `directionality`, `tenant_id` | `VARCHAR` | |
| `extra` | `JSON` | Remaining fields (`message-info`, `original-client-ip`, `custom-data`, `schema-version`, ...) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `exchange_logs`

Catchall for every other Exchange CSV log type (HttpProxy, ActiveSync/Eas,
Ews, Imap, Pop, RpcHttp, ...). Exchange ships over a dozen such
self-describing logs; rather than hand-modeling each, every field is
preserved verbatim -- still fully queryable, just not promoted to
first-class columns. Partition columns: `host, log_type`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `log_type` | `VARCHAR` | From the log file's `#Log-type:` header, e.g. `HttpProxy` (partition key) |
| `time_created` | `TIMESTAMP` | Best-effort, from the first datetime-shaped field |
| `fields` | `JSON` | The full self-described CSV row, keyed by its `#Fields:` header -- query with `fields ->> 'field-name'` |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `syslog`

Generic BSD/RFC-3164 (with or without a `<PRI>` prefix -- most real-world
`/var/log/syslog`/`messages`/`auth.log` files use rsyslog's default
template, which omits it) and RFC 5424 syslog lines: `/var/log/syslog`,
`messages`, `kern.log`, `daemon.log`, `mail.log`, `cron.log`,
`auth.log`/`secure`, and anything else sharing this line format.
`auth.log`/`secure` are **not** a separate table -- see `Case.auth_events()`
/ `seclogx auth` for a curated, structured view over the SSH/sudo/PAM
subset of this table. Partition column: `host`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `time_created` | `TIMESTAMP` | Log entry timestamp. BSD-format lines have no year in the wire format; it's inferred from the file's mtime (see known_limitations) |
| `hostname` | `VARCHAR` | Syslog-reported hostname -- may differ from analyst-assigned `host` |
| `facility` | `VARCHAR` | `kern`/`user`/`mail`/`daemon`/`auth`/`cron`/`authpriv`/`local0`-`7`/...; NULL if the line has no `<PRI>` |
| `severity` | `VARCHAR` | `emerg`/`alert`/`crit`/`err`/`warning`/`notice`/`info`/`debug`; NULL if the line has no `<PRI>` |
| `app_name` | `VARCHAR` | Program/tag, e.g. `sshd`, `CRON`, `sudo`, `kernel` |
| `proc_id` | `VARCHAR` | PID in brackets (BSD) or PROCID (RFC 5424) |
| `msg_id` | `VARCHAR` | RFC 5424 MSGID only, NULL for BSD-format lines |
| `message` | `VARCHAR` | Free-text message body |
| `structured_data` | `JSON` | RFC 5424 SD-ELEMENTs, keyed by SD-ID; NULL for BSD-format lines or SD-DATA `-` |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `auditd_logs`

Linux Audit Framework (`/var/log/audit/audit.log`) records, one row per
*line*. A real audit event is often several related lines (e.g. SYSCALL +
EXECVE + CWD + PATH) sharing one `audit_serial` -- these are not stitched
back together; correlate them yourself with `WHERE audit_serial = ...`
(see known_limitations). `syscall` is the raw number as reported, not
resolved to a name (the syscall table is architecture-dependent).
Partition columns: `host, record_type`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `time_created` | `TIMESTAMP` | From `msg=audit(epoch.ms:serial)` |
| `audit_serial` | `BIGINT` | The `audit(epoch:SERIAL)` id -- ties related lines together |
| `record_type` | `VARCHAR` | `SYSCALL` / `EXECVE` / `CWD` / `PATH` / `USER_AUTH` / `CRED_ACQ` / ... (partition key) |
| `syscall` | `VARCHAR` | Raw `syscall=` number as text -- not resolved to a name |
| `success` | `VARCHAR` | `yes`/`no` as reported; not every `record_type` has one |
| `exe`, `comm` | `VARCHAR` | Executable path / command name |
| `uid`, `auid` | `VARCHAR` | Effective uid, and loginuid (`auid` survives `su`/`sudo`) |
| `pid`, `ppid` | `VARCHAR` | Process / parent process id |
| `key` | `VARCHAR` | The triggering audit rule's `-k` tag, when set |
| `fields` | `JSON` | Every `key=value` pair on the line not promoted above, verbatim |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `journal_logs`

systemd journal export format (`journalctl -o json`), one JSON object per
line -- the standard log source on modern systemd distros. Not the same
as the binary journal itself (`/var/log/journal/**`), which isn't parsed.
Partition column: `host`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `time_created` | `TIMESTAMP` | From `__REALTIME_TIMESTAMP` (microseconds since epoch) |
| `hostname` | `VARCHAR` | `_HOSTNAME` |
| `unit` | `VARCHAR` | `_SYSTEMD_UNIT` |
| `syslog_identifier` | `VARCHAR` | `SYSLOG_IDENTIFIER` |
| `priority` | `VARCHAR` | `PRIORITY` (0-7, syslog severity scale) |
| `pid`, `uid` | `VARCHAR` | `_PID` / `_UID` |
| `comm`, `exe` | `VARCHAR` | `_COMM` / `_EXE` |
| `message` | `VARCHAR` | `MESSAGE` |
| `fields` | `JSON` | Every other journal field verbatim (`_TRANSPORT`, `_BOOT_ID`, custom structured-logging fields, ...) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

## `db_logs`

Database server logs: MySQL/MariaDB (error log, general query log, and
slow query log), PostgreSQL (stderr-format log), MSSQL (`ERRORLOG`), and
Oracle (alert log). Each sub-format is unambiguous from its own content
but structurally different from the others -- same reasoning as
`web_error_logs` unifying nginx/Apache/Tomcat/IIS HTTPERR -- so they
share one table with a `log_type` discriminator rather than one table
per engine. See `docs/known_limitations.md` for the content-sniffing
caveats specific to each sub-format. Partition columns: `host, log_type`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `log_type` | `VARCHAR` | `mysql_error` \| `mysql_general` \| `mysql_slow` \| `postgresql` \| `mssql` \| `oracle` (partition key) |
| `time_created` | `TIMESTAMP` | Log entry timestamp |
| `severity` | `VARCHAR` | mysql_error: `Note`/`Warning`/`ERROR`/`System`; postgresql: `LOG`/`ERROR`/`WARNING`/`FATAL`/... ; NULL for mysql_general/mysql_slow/mssql/oracle |
| `component` | `VARCHAR` | mysql_error's subsystem tag (e.g. `InnoDB`); mssql's spid/component token; mysql_general's `Command` (`Query`/`Connect`/...); NULL elsewhere |
| `error_code` | `VARCHAR` | mysql_error's `MY-XXXXX` code; oracle's `ORA-#####` extracted from the alert message text; NULL elsewhere |
| `thread_id` | `VARCHAR` | mysql thread/connection `Id`; postgresql's pid; mssql's spid digits; NULL for oracle |
| `user_name` | `VARCHAR` | mysql_slow's `User@Host` user; postgresql's connected user; NULL elsewhere |
| `database_name` | `VARCHAR` | postgresql's connected database; NULL elsewhere |
| `client_address` | `VARCHAR` | mysql_slow's `User@Host` host/IP part; NULL elsewhere |
| `query_time_sec` | `DOUBLE` | mysql_slow's `Query_time`, in seconds; NULL elsewhere |
| `rows_examined` | `BIGINT` | mysql_slow's `Rows_examined`; NULL elsewhere |
| `message` | `VARCHAR` | Free-text message / SQL statement text / mysql_general's argument |
| `extra` | `JSON` | Catchall (e.g. mysql_slow's `lock_time`/`rows_sent`) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |
