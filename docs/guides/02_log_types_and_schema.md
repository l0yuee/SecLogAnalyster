# 2. Log types and schema

**Language: English | [中文](02_log_types_and_schema.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | 02. Log types & schema | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

This guide answers "what does each table hold, and what should I actually
look at first" for the log families seclogx normalizes. For the exact
column-by-column reference (types, nullability, partition keys), see
`docs/schema.md`; for how each format is ingested, see `docs/architecture.md`.

## The normalized `events` schema

Every record from every channel, regardless of provider, is normalized
into the same set of columns -- see `docs/schema.md` for the full list.
The most important ones for day-to-day querying:

| Column | What it is |
|---|---|
| `time_created` | Event timestamp, UTC |
| `host` | The host label *you* assigned at ingest time |
| `computer` | The hostname embedded in the log itself (can differ from `host`) |
| `channel` | e.g. `Security`, `Microsoft-Windows-Sysmon/Operational` |
| `event_id` | Windows Event ID |
| `provider_name` | Event provider |
| `process_id` / `thread_id` | Generating process/thread |
| `user_sid` | Security context SID |
| `event_data` | Provider-specific fields as JSON (see below) |
| `source_file` / `source_path` / `file_sha256` | Provenance / chain of custody |

## Encoding and EVTX recovery

Text classification and full-file decoding share the same policy. UTF-16 needs a
BOM or strong interleaved NUL/ASCII evidence; even-sized GBK input does not select
UTF-16. A 16 KiB classification prefix may end inside a multibyte character.
Other text tries strict UTF-8, GB18030, then Latin-1. Ambiguous BOM-less text can
still be misidentified.

EVTX recovery continues beyond recoverable chunk errors. Source reports preserve
recovered counts, errors and `header_record_count`, derived from physical record
ordinals in valid chunk headers. This is a consistency check, not a guarantee for
all damaged records. `partial` requires reviewing recovery warnings. Conversion
count mismatches, I/O failures and detected source changes abort the attempt.

EVTX ANSI fields depend on the source Windows code page, independently of Unicode
fields. The explicit fallback is `windows-1252`; the analyst computer's locale is
not used to guess evidence encoding. Supply known source metadata when available:

```python
from pathlib import Path
from seclogx import SourceSpec

report = c.ingest([SourceSpec(Path("evidence/Security.evtx"), host="HOST01", ansi_codec="gbk")])
report.to_dataframe()[["source_file", "ansi_codec", "ansi_codec_source", "status", "record_count"]]
```

`cp936` is also accepted for GBK. Reports identify whether the code page came from
source metadata or the default. Different host labels or decoding semantics are
distinct imports even when the underlying source bytes match.

## The `event_data` field

Everything provider-specific (Sysmon's `Image`, `CommandLine`,
`ParentImage`; Security's `TargetUserName`, `LogonType`; etc.) lives in
one `event_data` JSON column, because the set of fields varies
enormously by provider and event type. Pull a field out with DuckDB's
`->>` operator:

```sql
SELECT (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
```

> **Always parenthesize `(event_data ->> 'Field')` whenever your `WHERE`
> clause combines it with another condition via `AND`/`OR`/`LIKE`.**
> DuckDB's `->`/`->>` operators don't bind as tightly as you'd expect
> against `LIKE`/`AND` in a compound expression -- an unparenthesized
> `event_data ->> 'Image' LIKE '%foo%' AND ...` can misparse and fail at
> execution time with a confusing type-cast error (`Could not convert
> string '{...}' to BOOL`), rather than a clear syntax error. Wrapping
> the extraction in parens, as in every example in this guide, avoids it
> entirely. A single, standalone `event_data ->> 'Field'` with no other
> `AND`/`OR` in the query is fine either way.

If you don't know the exact field name for something, `CaseDB.search()`
/ `seclogx query ... event_data::VARCHAR ILIKE '%...%'` does a full-text
search across it -- see [07. Recipes](07_recipes.md) -- or read on for
`seclogx fields`, which lists real field names directly from your data.

## The other tables: `web_logs`, `web_error_logs`, `scheduled_tasks`, `exchange_message_tracking`, `exchange_logs`, `syslog`, `auditd_logs`, `journal_logs`, `db_logs`, `qcloud_logs`, `aegis_logs`, `registry`

Windows Event Log isn't the only artifact `ingest` normalizes. Each of
these is fundamentally a different shape, so each gets its own table
rather than being crammed into `events` -- full column reference in
`docs/schema.md`. Every one of them is also reachable as a plain
`pandas.DataFrame` through a named `Case` accessor (`c.web_logs()`,
`c.scheduled_tasks()`, ...), the same first-class treatment `events` gets
via `summary()`/`hosts()`/`channels()` -- see [06. Python API](06_python_api.md).

The normalized columns are the same for both staging formats. By default,
staged source files, including EVTX, at least 16 MiB use Arrow IPC/ZSTD level 1;
smaller files use gzip NDJSON. Both apply fixed input types and canonical
casts, so missing/invalid typed values become `NULL` without reinterpreting
timestamp-shaped free text. JSON columns such as `extra` and `fields`
are physically text containing JSON. Explicit timestamp offsets are
normalized to UTC; timestamps without offsets keep their wall-clock value.

Ingest emits records as they are parsed, but this does not make a full-table
DataFrame small. Use the `_chunks` accessors for large query results; see
[03. Querying and search](03_querying_and_search.md). Staging completes
before flattening within each pipeline, and source files above 2 GiB are
accepted subject to parser/record limits.

| Table | What it holds | Key columns |
|---|---|---|
| `web_logs` | **Access logs**: IIS, nginx, Apache, and Tomcat HTTP access logs, unified | `log_type`, `client_ip`, `method`, `uri_stem`, `uri_query`, `status`, `user_agent`, `referer` |
| `web_error_logs` | **Error/diagnostic logs**: nginx, Apache, Tomcat, and IIS HTTP.sys (HTTPERR) -- the other major web-application log category, unified | `log_type`, `severity`, `client_ip`, `message`, plus IIS HTTPERR's `method`/`uri`/`status` |
| `scheduled_tasks` | On-disk Task Scheduler task definitions (`System32\Tasks\**`) -- a persistence artifact, distinct from the Task Scheduler *event log* (already in `events`) | `task_path`, `author`, `enabled`, `hidden`, `action_command`, `action_arguments`, `action_types`, `trigger_types`, `actions` (JSON), `triggers` (JSON) |
| `exchange_message_tracking` | Exchange mail flow (who sent what to whom) | `sender_address`, `recipient_address`, `message_subject`, `event_id` (Exchange's own, not a Windows Event ID) |
| `exchange_logs` | Every other Exchange CSV log type (HttpProxy, ActiveSync, EWS, ...), fields preserved verbatim | `log_type`, `fields` (JSON, query with `fields ->> 'field-name'`) |
| `syslog` | Generic BSD/RFC-3164 and RFC 5424 syslog: `/var/log/syslog`, `messages`, `kern.log`, `auth.log`/`secure`, etc., unified | `app_name`, `hostname`, `facility`, `severity`, `message`, `structured_data` (JSON, RFC5424 only) |
| `auditd_logs` | Linux Audit Framework (`/var/log/audit/audit.log`), one row per line | `record_type`, `audit_serial`, `syscall`, `exe`, `comm`, `auid`, `key`, `fields` (JSON) |
| `journal_logs` | systemd journal export format (`journalctl -o json`) | `unit`, `syslog_identifier`, `priority`, `comm`, `exe`, `message`, `fields` (JSON) |
| `db_logs` | Database server logs: MySQL/MariaDB (error, general query, slow query), PostgreSQL, MSSQL, Oracle alert log, unified | `log_type`, `severity`, `error_code`, `thread_id`, `user_name`, `query_time_sec`, `rows_examined`, `message` |
| `qcloud_logs` | Tencent Cloud Host Security client text logs: YDService, HIDS/YDLive, vulnerability/baseline scanners, YDFlame/YDUtils/YDQuaraV2, YDEyes | `log_type`, `severity`, `module`, `event_type`, `user_name`, `source_ip`, `file_path`, `file_md5`, `message`, `extra` |
| `aegis_logs` | Alibaba Cloud Security Center (Aegis) Linux client text logs: AliSecCheck, AliSecCheckTmp, AliHips, PythonLoader, client/monitor and updater | `log_type`, `component`, `logger`, `severity`, `event_type`, `task_name`, `task_id`, `duration_ms`, `message`, `raw_line` |
| `registry` | Windows Registry hives: SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT/NTUSER/UsrClass/AmCache, one row per value | `hive_type`, `full_path`, `value_name`, `value_type`, `value_text`, `value_int`, `entropy` |

A few things worth knowing before you query these:

- **Format is detected by content, not filename or extension** -- a live
  Task Scheduler task file has no extension at all, and forensic tools
  routinely rename exported logs. A file matching none of the supported
  formats after classification is reported as unrecognized in the ingest
  summary. Empty files, configured skipped suffixes and unreadable paths
  are not all represented in that count; see [known limitations](../known_limitations.md).
- **`web_logs` covers the access-log category; `web_error_logs` covers the
  error/diagnostic-log category** -- the two major log categories every
  web application produces. They're separate tables because they're
  structurally unrelated (access logs have a request/response shape;
  error logs are just severity + free text).
- **In `web_logs`, nginx vs. Apache vs. Tomcat is a best-effort label**,
  not a hard detection -- Common/Combined Log Format is byte-identical
  across all three; `log_type` falls back to `web_access` when no
  path/filename hint is available. IIS identification uses its
  self-describing header; missing or nonstandard headers can still fail detection.
- **In `web_error_logs`, the engine label *is* a real detection** -- each
  engine's error-log format is distinct and unambiguous, unlike access
  logs. Only each engine's default/standard format is recognized (a
  customized `log_format`/`ErrorLogFormat`, or raw unstructured stdout
  mixed into Tomcat's `catalina.out`, produces reported parse errors for
  those lines rather than a misparse).
- **Exchange support is scoped to Message Tracking as first-class
  columns**; every other Exchange log type (there are over a dozen)
  lands in `exchange_logs` with all fields preserved in `fields`, still
  fully queryable, just not promoted to real columns.
- **`auth.log`/`secure` are not their own table or format** -- they're
  `syslog`-format lines like any other, just with recognizable program
  names (`sshd`, `sudo`, `su`, `useradd`, ...) in them. `Case.auth_events()`
  / `seclogx auth` derives a curated, structured view (SSH accept/fail,
  sudo commands, PAM session open/close, account management) from
  `syslog` rows already ingested -- not a separate ingest table, the same
  pattern `suspicious_tasks()` uses over `scheduled_tasks`.
- **`syslog.facility`/`severity` are NULL unless the line has a `<PRI>`
  prefix** -- the common rsyslog default file template omits it entirely,
  so this is a property of the log format, not a parsing gap.
- **`auditd_logs.syscall` is the raw number, not a resolved name** -- the
  Linux syscall table is architecture-dependent. A real audit event is
  often several related lines (SYSCALL + EXECVE + CWD + ...) sharing one
  `audit_serial`; these aren't stitched together automatically -- filter
  on `audit_serial` yourself to see them all.
- **`journal_logs` parses the journal *export* format** (`journalctl -o
  json`), not the binary journal itself (`/var/log/journal/**`), which
  isn't portable across systems and isn't ingested.
- **`db_logs` unifies six sub-formats behind `log_type`**: `mysql_error`,
  `mysql_general`, `mysql_slow`, `postgresql`, `mssql`, `oracle`. Only
  `mysql_slow` populates `query_time_sec`/`rows_examined`/`client_address`;
  `user_name` also comes from PostgreSQL when present. Only
  `mysql_error`/`oracle` populate `error_code`;
  columns an engine doesn't produce are simply NULL for its rows -- see
  `docs/schema.md` for exactly which columns each sub-format fills in.
  Detection is content-based like every other table here, but MySQL's
  general/slow query logs and Oracle's alert log each depend on a
  marker/header/timestamp line appearing early in the file -- see
  `docs/known_limitations.md` if a database log doesn't get picked up.
- **`qcloud_logs` unifies four client line envelopes behind `log_type`**.
  Stable login, malware, quarantine, command, blocklist, and account messages
  receive structured fields; every message remains searchable verbatim. The
  generic-looking Go/scanner/YDEyes envelopes require Tencent product context,
  and private-cloud upload payloads are not decoded; see
  `docs/known_limitations.md`.
- **`registry` is not a live merged registry** -- no `HKLM`/`HKCU`
  aliasing, no volatile keys. Each row is rooted at its own hive's real
  logical path (`hive_root` + `key_path`, e.g.
  `HKEY_LOCAL_MACHINE\SOFTWARE\...`, `HKEY_USERS\<user>\...`) -- the same
  per-hive presentation forensic registry tools already use. One row per
  value, plus one row per key with zero values (so key existence/
  last-write-time isn't lost); `entropy` is populated only for
  binary-typed values. See `docs/known_limitations.md` for the
  transaction-log-recovery and hive-type-identification caveats. Traversal
  reads a seekable hive file, but recovery and individual large values can
  still consume substantial memory. Stored binary hex covers the first
  8 KiB of bytes; entropy uses the full binary value.
- See [07. Recipes](07_recipes.md) for recipes, and `docs/known_limitations.md`
  for the full list of scope decisions.

## Quick reference: analyzing each log type

Every table below is always reachable the fully generic way regardless of
whether it has a dedicated interface: `seclogx query <case> "<SQL>"` /
`seclogx table <case> <name>` on the CLI, and `Case.query()`/
`Case.db.table(name)` (plus their `_chunks` siblings) in Python -- or,
if you'd rather not write SQL at all, `seclogx search <case> <table>` /
`Case.search()` (plain field/value conditions: exact, fuzzy, or regex
matching -- see [03. Querying & search](03_querying_and_search.md)). The
columns below are the *additional*, purpose-built interfaces each table
gets on top of that.

| Log type | Table | Dedicated CLI | Dedicated Python (eager / chunked) | Sigma hunting |
|---|---|---|---|---|
| Windows Event Log | `events` | `summary`, `channels`, `timeline`, `hunt` | `summary()`/`channels()`/`hosts()`, `events()` / `events_chunks()`, `timeline()` / `timeline_chunks()` | Yes -- most bundled rule categories |
| Web access logs (IIS/nginx/Apache/Tomcat/Exchange-HttpProxy) | `web_logs` | none -- use `table web_logs` / `query` | `web_logs(log_type=)` / `web_logs_chunks(log_type=)` | Yes -- `category: webserver` (bring your own rules; none bundled by default) |
| Web error logs (nginx/Apache/Tomcat/IIS HTTPERR) | `web_error_logs` | none -- use `table web_error_logs` / `query` | `web_error_logs(log_type=)` / `web_error_logs_chunks(log_type=)` | No -- query directly |
| Scheduled Tasks | `scheduled_tasks` | `tasks [--suspicious]` | `scheduled_tasks()` / `scheduled_tasks_chunks()`, `suspicious_tasks()` (heuristic) | No -- use `suspicious_tasks()` / query directly |
| Exchange Message Tracking (mail flow) | `exchange_message_tracking` | none -- use `table exchange_message_tracking` / `query` | `exchange_message_tracking()` / `exchange_message_tracking_chunks()` | No -- query directly |
| Other Exchange logs (HttpProxy, EWS, EAS, ...) | `exchange_logs` | none -- use `table exchange_logs` / `query` | `exchange_logs(log_type=)` / `exchange_logs_chunks(log_type=)` | No -- query directly |
| Linux syslog (incl. `auth.log`/`secure`) | `syslog` | `auth` (curated SSH/sudo/PAM view) | `syslog()` / `syslog_chunks()`, `auth_events()` (heuristic) | No -- use `auth_events()` / query directly |
| Linux Audit Framework (auditd) | `auditd_logs` | none -- use `table auditd_logs` / `query` | `auditd_logs()` / `auditd_logs_chunks()` | No -- query directly |
| systemd journal export | `journal_logs` | none -- use `table journal_logs` / `query` | `journal_logs()` / `journal_logs_chunks()` | No -- query directly |
| Database logs (MySQL/MariaDB/PostgreSQL/MSSQL/Oracle) | `db_logs` | none -- use `table db_logs` / `query` | `db_logs(log_type=)` / `db_logs_chunks(log_type=)` | No -- query directly |
| Tencent Cloud Host Security client logs | `qcloud_logs` | none -- use `table qcloud_logs` / `query` | `qcloud_logs(log_type=)` / `qcloud_logs_chunks(log_type=)` | No -- query directly |
| Alibaba Cloud Security Center (Aegis) client logs | `aegis_logs` | none -- use `table aegis_logs` / `query` | `aegis_logs(log_type=)` / `aegis_logs_chunks(log_type=)` | No -- use search/SQL |
| Windows Registry hives | `registry` | `registry [--suspicious] [--hive-type]` | `registry(hive_type=)` / `registry_chunks(hive_type=)`, `suspicious_registry()` (heuristic) | No -- use `suspicious_registry()` / query directly |

`seclogx sources <case>` isn't table-specific -- it's the one command to
run first, before any of the above: a row count per table so you know
what the case actually has before picking which of these to reach for.

What to actually look for in each, at a glance (full recipes in
[07. Recipes](07_recipes.md)):

- **`events`** -- the day-to-day DFIR core: process creation
  (parent/child chains, LOLBins), logon activity by type, PowerShell
  script blocks, registry/file changes. Start with `summary()`/
  `channels()` to see what actually got captured (was Sysmon running?),
  then `hunt()` for a first pass.
- **`web_logs`** -- anomalous status codes, uncommon URI extensions
  hit with a 200 (possible webshells), suspicious user agents, one
  client IP dominating traffic.
- **`web_error_logs`** -- error spikes correlated with `web_logs`
  anomalies at the same timestamp; IIS HTTPERR specifically catches
  requests HTTP.sys itself rejected *before* reaching an IIS worker
  process, so it can surface exploitation attempts that never show up
  in `web_logs` at all.
- **`scheduled_tasks`** -- persistence hunting: hidden or unauthored
  tasks, actions invoking a LOLBin, action paths under Temp/AppData/
  Public, or a known Microsoft task path whose action doesn't match its
  expected executable location (a hijacked/masqueraded legitimate task,
  MITRE ATT&CK T1053.005). `suspicious_tasks()` runs all of this for you
  and explains *why* each row was flagged via a `suspicion_reasons`
  column; `scheduled_tasks()` returns the full table (including
  first-class `action_command`/`action_arguments`/`action_types` columns
  derived from the raw `actions` JSON) for open-ended analysis.
- **`exchange_message_tracking`** -- phishing and mail-based
  exfiltration: sender/recipient/subject sweeps, unexpected external
  mail flow, a sender domain that doesn't match its claimed identity.
- **`exchange_logs`** -- Exchange HTTP-based compromise (e.g.
  ProxyShell-style attacks) where the relevant activity is in
  HttpProxy/OWA/ECP access patterns rather than mail flow -- sweep
  `fields` by content when you don't know the exact schema.
- **`syslog`** -- start with `auth_events()` for SSH/sudo/PAM/account
  triage (failed logins by source IP, invalid-user probing, sudo command
  history for a user); query `syslog` directly by `app_name`/`facility`
  for anything else (cron activity, kernel messages, mail transport).
- **`auditd_logs`** -- process execution and privilege-escalation
  auditing on hosts with audit rules configured: sweep by `key` (the
  triggering rule's tag) or `exe`/`comm`, then pull every line sharing
  that row's `audit_serial` to see the full SYSCALL/EXECVE/CWD/PATH
  picture for one event.
- **`journal_logs`** -- the systemd-native equivalent of `syslog` on
  hosts where the analyst exported `journalctl -o json` instead of (or in
  addition to) a forwarded syslog file; sweep by `unit`/`syslog_identifier`
  to see everything one service logged.
- **`db_logs`** -- authentication failures and errors surfaced by
  `error_code` (MySQL's `MY-XXXXX`, Oracle's `ORA-#####` -- e.g.
  `ORA-01017` is invalid credentials, a brute-force signal) or `severity`
  (`ERROR`/`FATAL` in PostgreSQL); `mysql_slow` rows with a high
  `rows_examined` relative to typical traffic (possible data
  exfiltration via a full-table scan); `message` text for SQL injection
  patterns reaching the database layer. Filter by `log_type` first --
  the six sub-formats have very different columns populated.
- **`qcloud_logs`** -- start with `event_type` to surface login failures,
  malware detections/scans, blocklist decisions, and scanner command
  execution. Pivot with `source_ip`, `user_name`, `file_md5`, `file_path`,
  `subject_process_id`, and `trace_id`; use `module` and `message` for
  component-specific activity not covered by enrichment.
- **`aegis_logs`** -- start with `log_type`, `component`, `severity` and
  `message` to reconstruct client activity. Recognized task-lifecycle records
  can be correlated by `task_name`/`task_id`; a task starting or completing
  does not by itself indicate a security detection. Keep the original record
  and source provenance when investigating a possible finding.
- **`registry`** -- `suspicious_registry()` runs first: Run/RunOnce
  startup items, service `ImagePath`/`ServiceDll`, COM CLSID
  `InprocServer32` hijacking, Winlogon `Shell`/`Userinit`/`Notify`
  tampering, `AppInit_DLLs`, Image File Execution Options `Debugger`
  hijacks, and high-`entropy` binary values (`WHERE entropy > 7.5` finds
  likely encoded/packed payloads stashed in a registry value directly).
  For open-ended digging, `full_path`/`value_name` sweeps by known
  persistence locations, or `key_last_write_time` to spot recently
  modified keys around an incident window.

## Alibaba Cloud Security Center (Aegis)

Pass an acquired Aegis directory to ordinary ingest, preserving its subdirectory
layout when possible. No extra dependency or parser switch is needed:

```python
from seclogx import Case, SourceSpec

c = Case.create("aegis-review")
report = c.ingest([SourceSpec("/evidence/aegis", host="LINUX01")])
c.table_counts()
c.fields("aegis_logs")
```

The following paths are relative to the acquired `aegis` root (normally
`/usr/local/aegis` on the source host). A matching supported text header is
required as well as path/product context; this is not a whitelist accepting
every file in these directories.

| Acquired path | `log_type` | Context |
|---|---|---|
| `AliSecCheck/data/detect/log` | `detect` | Detection component |
| `AliSecCheck/data/rtap/log` | `rtap` | Real-time protection component |
| `AliSecCheck/data/debug_hips.log` | `hips_debug` | HIPS diagnostics |
| `globalcfg/AliHips/log` | `hips` | Host intrusion prevention component |
| `data/atd_lnx_reverse_shell.log` | `reverse_shell` | Reverse-shell checking component |
| `PythonLoader/data/*.log`, `PythonLoader/data/data.<number>.N` | `python_loader` | Python loader checks |
| `AliSecCheckTmp/data/*/log` | `security_check`; `detect`/`rtap` for those named subdirectories | Temporary security-check component |
| `AliSecCheckTmp/data/data.N` | `security_check` | Temporary security-check component |
| Other recognized `AliSecCheck/data/*.log` / `AliSecCheckTmp/data/*.log` | `security_check`, or a more specific subtype above | Component operational/configuration diagnostics |
| `aegis_client/<version>/data` | `client` | Client component (`component=AegisClient`) |
| `aegis_client/<version>/yun_dun_monitor_log` | `monitor` | Client monitor (`component=AegisClient`) |
| `aegis_update/data` | `update` | Updater (`component=AegisUpdate`) |

Plain-text rotations such as `data.N` and `data.<number>.N` use the same parser;
`N` and `<number>` stand for numeric filename segments. `agent` is the
fallback subtype when the available context does not establish a more specific
one. File names containing `config` can still be logs when their contents have
the supported log layout; configuration documents and binaries are not parsed
as log records merely because they share a directory.

```python
# A whole-table accessor is suitable only when the selected data is small.
c.aegis_logs(log_type="hips")

# Process and release each chunk for larger sources.
for chunk in c.aegis_logs_chunks(log_type="detect", chunksize=10_000):
    print(chunk[["time_created", "severity", "task_name", "message"]].head())

c.search("aegis_logs", eq={"event_type": "task_completed"})
```

`raw_line` retains complete multiline text, including line endings and blank
lines. Complete JSON objects/arrays can also appear under `extra.json_payload`;
payloads containing invalid Unicode or exceeding JSON depth limits stay as raw
text without interrupting later records. Python representation text stays as
text and is never executed. Only
recognized scheduling messages are labeled `task_queued`, `task_started` or
`task_completed`. The log category and severity do not constitute a security
alert verdict. `context_id` is an opaque numeric string, not an inferred PID or
thread ID. The core header `timestamp [number] message` has no severity, so
`severity` is NULL. Timestamps retain source wall-clock time; supply the host's timezone
knowledge when correlating other evidence. Proprietary binary files and
compressed rotations need separate preparation; coverage of every client
version is not guaranteed. A logical record above 4,194,304 characters or
100,000 physical lines produces an explicit error, not a truncated row.
Earlier complete records may remain as partial recovery; inspect the ingest
report. See the
[column reference](../schema.md#aegis_logs) and
[limits](../known_limitations.md#alibaba-cloud-security-center-aegis-client-log-ingestion).

## Which fields can I search on?

Two questions come before writing any search: *what fields does this
table actually have*, and *which one is the right one for what I'm
trying to find*. `seclogx fields <case> <table>` / `Case.fields()`
answers the first directly from this case's real, ingested data (not a
static list -- a `web_logs` field list looks different depending on what
a site's IIS admin chose to log, and `event_data`'s keys are entirely
provider-specific, so no fixed list would be accurate for every case
anyway):

```bash
seclogx fields incident42 events
```
```
                    Fields in events (sampled)
  field          where              seen_in_sample  example
  channel        column             102451          Microsoft-Windows-Sysmon/Operational
  event_id       column             102451          1
  host           column             102451          WKS01
  ...
  Image          inside event_data  41200           C:\Windows\System32\cmd.exe
  CommandLine    inside event_data  41200           cmd.exe /c whoami
  TargetUserName inside event_data  8310            alice
  ...
```

Each row is a field name you can pass to `eq=`/`contains=`/`regex=`,
where it comes from (a real column, or a key found inside a JSON
catchall like `event_data`), how many of a sample of rows had it, and one
real example value -- so you can see the shape of the data (is
`CommandLine` quoted? is `status` a string or a number?) before writing a
condition against it. It's computed from a bounded sample (`--sample-size`,
default 5000 rows), never a full table scan, so it's safe to run against
a table of any size; a genuinely rare field can occasionally be missed if
it shows up in fewer than 1-in-`sample-size` rows.

```python
c.fields("events")     # -> Image, CommandLine, TargetUserName, ... (from event_data)
c.fields("web_logs")   # -> status, uri_stem, client_ip, ... (real columns)
```

For the second question -- which field actually gets you what you want --
a starting cheat sheet per log type (run `seclogx fields` on your own
case for the full, real list; provider/site-specific fields especially
vary):

| Table | Start with these fields |
|---|---|
| `events` (process creation, Sysmon EventID 1) | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes` |
| `events` (network connection, Sysmon EventID 3) | `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname` |
| `events` (file/registry, Sysmon EventID 11/13) | `Image`, `TargetFilename` / `TargetObject`, `Details` |
| `events` (PowerShell, EventID 4104) | `ScriptBlockText` |
| `events` (logon, Security EventID 4624/4625) | `TargetUserName`, `LogonType`, `IpAddress` |
| `events` (always available, any channel) | `channel`, `event_id`, `host`, `computer`, `time_created`, `user_sid` |
| `web_logs` | `uri_stem`, `uri_query`, `status`, `method`, `client_ip`, `user_agent`, `referer`, `log_type` |
| `web_error_logs` | `severity`, `message`, `client_ip`; IIS HTTPERR only: `method`, `uri`, `status` |
| `scheduled_tasks` | `author`, `hidden`, `enabled`, `action_command`, `action_arguments`, `actions`, `triggers`, `task_path`, `principal_user_id` |
| `exchange_message_tracking` | `sender_address`, `recipient_address`, `message_subject`, `recipient_status`, `event_id` |
| `exchange_logs` | `log_type` first (to see what kind of Exchange log you actually have), then `seclogx fields` for that log type's real field names |
| `syslog` | `app_name`, `message`, `hostname`, `facility`/`severity` (NULL unless the source has `<PRI>`) |
| `auditd_logs` | `record_type`, `key`, `exe`, `comm`, `auid`, `audit_serial` (to correlate related lines) |
| `journal_logs` | `unit`, `syslog_identifier`, `message`, `priority` |
| `db_logs` | `log_type` first, then `severity`, `error_code`, `message`; `mysql_slow` rows also have `query_time_sec`, `rows_examined` |
| `qcloud_logs` | `event_type`, `module`, `severity`, `source_ip`, `user_name`, `file_md5`, `file_path`, `trace_id`, `message` |
| `aegis_logs` | `log_type`, `component`, `severity`, `task_name`, `task_id`, `event_type`, `duration_ms`, `message` |
| `registry` | `full_path`, `value_name`, `value_text`, `entropy`, `hive_type` |

For `events` specifically, note that which fields exist depends on the
*channel* -- `Image`/`CommandLine` are Sysmon fields and won't appear on
a Security-channel logon event, and vice versa for `TargetUserName`/
`LogonType`. `seclogx fields` samples across the whole table, so if you
want the fields for one specific channel, filter first (see
[07. Recipes](07_recipes.md), most of which start with `channel = '...'`).

Next: [03. Querying & search](03_querying_and_search.md) for how to
actually turn these field names into a query, with or without SQL.
