# Normalized schemas

Column reference for every table a case can have. This file covers two
sources: the Windows Event Log schema below (`src/seclogx/schema.py`),
and every other log family's schema further down (`## Non-EVTX log
tables`, from `src/seclogx/ingest/logsources/schema.py`) -- `events`,
`web_logs`, `web_error_logs`, `scheduled_tasks`,
`exchange_message_tracking`, `exchange_logs`. See "Quick reference:
analyzing each log type" in
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
| `actions` | `JSON` | List of `{type, ...}` -- every action element captured generically (Exec/ComHandler/SendEmail/ShowMessage) |
| `triggers` | `JSON` | List of `{type, ...}` -- every trigger element captured generically (TimeTrigger/LogonTrigger/BootTrigger/...) |
| `source_path`, `source_file`, `file_sha256`, `ingest_batch_id`, `ingested_at`, `schema_version` | | Provenance |

`Case.suspicious_tasks()` / `seclogx tasks <case> --suspicious` apply a
lightweight heuristic (action path under Temp/AppData/Public, or a
LOLBin-like command, or a hidden/unauthored task) -- not a Sigma rule,
since Sigma has no logsource category for on-disk task definitions.

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
