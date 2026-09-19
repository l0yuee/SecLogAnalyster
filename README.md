# seclogx

Fast, pandas-friendly threat hunting over forensic acquisitions. Built for
DFIR/malware analysis workflows: point it at scattered acquisition
directories from multiple hosts, get back a queryable, huntable case
workspace instead of raw XML and inconsistent text logs.

- **Windows Event Log (`.evtx`) -- every channel** (Security, System,
  Application, Sysmon Operational, PowerShell Operational, WMI-Activity,
  ...) parsed generically, not a hand-picked subset.
- **Scheduled Tasks**: on-disk Task Scheduler XML definitions
  (`System32\Tasks\**`), a persistence artifact distinct from the Task
  Scheduler event log channel (also covered, via `.evtx`).
- **IIS logs**: W3C Extended Log Format access logs, plus HTTP.sys
  (HTTPERR) error logs.
- **Cross-platform web logs**: nginx, Apache, and Tomcat -- both major log
  categories: access logs (Common/Combined Log Format, unified with IIS
  into one queryable table) and error/diagnostic logs (each engine's
  native error-log format, unified into a second table).
- **Exchange logs**: Message Tracking (mail flow, first-class columns) plus
  generic handling of recognized Exchange CSV logs that retains their fields.
- **Linux system logs**: generic syslog (BSD/RFC-3164 and RFC 5424 --
  `/var/log/syslog`, `messages`, `kern.log`, `auth.log`/`secure`, ...), the
  Linux Audit Framework (`auditd`), and systemd journal export
  (`journalctl -o json`). `auth.log`/`secure` content is recognized within
  `syslog` (not a separate table) -- `seclogx auth` / `Case.auth_events()`
  derives a curated SSH/sudo/PAM/account-management view from it.
- **Database logs**: MySQL/MariaDB (error, general query, and slow query
  logs), PostgreSQL, MSSQL (`ERRORLOG`), and Oracle (alert log) -- unified
  into one `db_logs` table with a `log_type` column, same pattern as the
  web access/error log tables.
- **Tencent Cloud Host Security logs**: Linux YunJing / Tencent CWPP
  `ydservice.*.log`, `hids.log*`, `ydlive.log`, scanner, asset, quarantine,
  and YDEyes text logs -- unified in `qcloud_logs`, with structured login,
  blocklist, malware/path/hash/trace, process, account, and command fields
  while retaining each complete raw record.
- **Windows Registry**: raw hive files (SYSTEM, SOFTWARE, SAM, SECURITY,
  DEFAULT, per-user `NTUSER.DAT`/`UsrClass.dat`) parsed completely --
  every key and value, not a sample -- into one `registry` table, with
  best-effort transaction-log (`.LOG1`/`.LOG2`) recovery for hives
  collected dirty. `seclogx registry --suspicious` /
  `Case.suspicious_registry()` flags high-entropy binary values (possible
  encoded/packed payloads) and known persistence techniques (Run/RunOnce,
  services, COM CLSID hijacking, Winlogon tampering, AppInit_DLLs, IFEO
  debugger hijacks).
- **Threat hunting built in**: Sigma rules (a curated bundled starter set,
  or your own) compiled to DuckDB SQL and run against the case, with
  MITRE ATT&CK tags surfaced on every match -- covers Windows Event Log
  and web access logs (`category: webserver`).
- **No SQL required.** `seclogx search` / `Case.search()` query any table
  with plain field/value conditions -- exact match, fuzzy/substring
  match, or regular expressions, case-insensitive by default, any number
  of conditions combined with AND/OR -- for analysts who'd rather not
  write SQL by hand. Not sure what fields exist or which one to search
  on? `seclogx fields` / `Case.fields()` lists table columns and JSON-catchall
  keys found in a bounded sample, with counts and example values.
- **pandas-native**: every log family -- events, web access/error logs,
  Scheduled Tasks, Exchange logs, syslog, auditd, systemd journal, database
  logs, Tencent Cloud Host Security logs, Registry hives -- is reachable as a `pandas.DataFrame` through a
  named accessor
  (`c.web_logs()`, `c.scheduled_tasks()`, `c.syslog()`, ...), the same
  first-class treatment `events` gets, ready for a notebook.
- **Chunked analysis for every log family.** Each log-table DataFrame accessor has a
  `_chunks()` sibling (`c.web_logs_chunks()`, `c.query_chunks()`,
  `c.search_chunks()`, ...) that streams the result as an iterator of
  DataFrames instead of one, and `--out`/console preview in the CLI use
  this for query, table, search and timeline output, so these exports and
  previews do not materialize the full result. `search()` also estimates
  result size against the machine's available memory before
  fetching, refusing (with the chunked/streamed alternative named in the
  error) when the estimate exceeds its budget. Row width and query execution
  still affect memory use; unchunked DataFrames and derived analyses can be large.
- **Handles realistic case volumes on a single workstation**, lazily --
  DuckDB + Parquet, no cluster required. An opt-in distributed mode is
  also available (job-queue-based ingest/hunt fan-out, S3-backed shared
  storage) for large ingest batches, large Sigma rule sets, or multiple
  analysts sharing one case -- purely environment-variable-activated, zero
  effect unless configured. See
  [10. Distributed deployment](docs/guides/10_distributed_deployment.md)
  and `deploy/`.
- **Reconciliation reports.** Discovered files have parsing status and recovered
  record counts; unrecognized classification candidates and unsupported Sigma
  rules are reported. Discovery filters known unrelated suffixes and empty
  files, and can skip inaccessible paths, so this is not a complete evidence
  inventory. See [known limitations](docs/known_limitations.md).

**Full documentation: [English](docs/index.md) | [中文](docs/index.zh-CN.md)**

See `docs/architecture.md` for how it works, `docs/schema.md` for every
table's normalized schema, `docs/sigma_backend.md` for the detection
engine, and `docs/known_limitations.md` for known v1 scope decisions and
edge cases.

## Install

Normal installation now includes the Rust parser; no separate accelerator
package or per-import performance switch is needed. **Installing this checkout
from source requires stable Rust/Cargo and a native compiler/linker.** On Windows,
install Visual Studio Build Tools with Desktop development with C++, MSVC tools
and a Windows SDK, then the stable MSVC Rust toolchain. Linux needs GCC or Clang;
macOS needs Xcode command-line tools. Complete commands and prerequisites:
[English installation guide](docs/guides/01_getting_started.md#install) |
[中文安装指南](docs/guides/01_getting_started.zh-CN.md#安装).

After preparing the build tools, run from the repository root:

```bash
conda activate python314
python -m pip install -e .
python -m pip install jupyterlab ipykernel
python -m ipykernel install --user --name python314 --display-name "Python (python314)"
python -m jupyterlab
```

The project uses conda **`python314`**, isolated from `base`; the installation
guide also covers creating it. Python >=3.10 is required. Pip installs the
build backend and Python dependencies automatically. With matching dependency
wheels, no separate DuckDB server or Arrow C++ installation is needed.
Installing a maintainer-built platform wheel requires no Rust compiler for
seclogx itself; this repository does not assume publicly available seclogx
wheels. After upgrades, repeat the project install and restart Jupyter kernels.

## Quickstart

```bash
# Create a case and ingest from one or more forensic acquisition paths --
# .evtx, Scheduled Task definitions, IIS/nginx/Apache/Tomcat access AND
# error logs, Exchange CSV logs, Linux syslog/auth.log, auditd, and
# systemd journal export logs, MySQL/PostgreSQL/MSSQL/Oracle database
# logs, Tencent Cloud Host Security logs, and raw Windows Registry hives are discovered and
# classified automatically in the same pass. Each --source can carry an
# explicit host label (PATH:HOST); if omitted, the source directory's
# name is used.
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01

# Alternative for a large import: start a separate case in the background.
# Do not re-import the same evidence into one case; imports are additive.
seclogx ingest large_case --source /evidence/full_kape_output --background
seclogx ingest-status large_case --watch

# See what's in it
seclogx summary incident42
seclogx channels incident42
seclogx sources incident42        # row count per table: events, web_logs, scheduled_tasks, syslog, ...
seclogx tasks incident42 --suspicious
seclogx auth incident42           # curated SSH/sudo/PAM view over syslog

# Ad hoc SQL (the `events` table is the normalized, Hive-partitioned lake)
seclogx query incident42 "
  SELECT time_created, computer, event_data ->> 'Image' AS image, event_data ->> 'CommandLine' AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
  LIMIT 20
"

# Not sure what fields exist? List them from the real ingested data
seclogx fields incident42 events

# Or the same thing without writing SQL: plain field/value conditions,
# fuzzy/exact/regex, case-insensitive by default
seclogx search incident42 events --contains Image=mimikatz --eq host=WKS01

# Hunt with the bundled curated Sigma rule set (or --rules <your dir>)
seclogx hunt incident42

# Cross-host timeline, filterable, exportable
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

## Python / notebook usage

Normal imports automatically select native parsing, bounded Arrow batches and
direct Parquet output for compatible local UTF-8 Common/Combined and IIS logs.
Other formats and incompatible inputs use the Python compatibility path.
Analysts keep the same API:

```python
from seclogx import Case

c = Case.create("new_case")
report = c.ingest([r"E:\evidence:HOST01"])
print(report.summary_text())
```

To keep the Notebook responsive, use `c.ingest_background(sources)` instead
of the foreground call, then poll `c.job_status(job_id)`. Wait for completion,
inspect the report and reopen the Case before analysis. Background execution
does not provide automatic resume or reduce the work itself.

Temporary staging is now removed after successful conversion by default;
**source evidence is never deleted**. Use `keep_staging=True` only when you need
the intermediate files for investigation; this selects the staging path.
Local defaults use up to eight parsing workers, 2GB per DuckDB conversion and
two conversion threads. These are work budgets, not a process-tree RSS cap.
Advanced overrides and format/publication boundaries are documented in
[Python API](docs/guides/06_python_api.md) and
[performance and scale](docs/guides/08_performance_and_scale.md)
([中文](docs/guides/08_performance_and_scale.zh-CN.md)).
Large analysis results still need filtered queries or `_chunks()` accessors.

```python
from seclogx import Case

c = Case.open("incident42")

c.summary()                       # pandas.DataFrame
c.query("SELECT * FROM events WHERE event_id = 4688 LIMIT 10")
c.hunt().matches                  # matched events/web_logs, tagged with rule + ATT&CK ids
c.hunt().rule_summary             # one row per rule evaluated, with match counts
c.timeline(host="WKS01", event_id=[4624, 4625])
c.table_counts()                  # what log families this case has

# Every log family is a first-class, DataFrame-returning accessor -- same as events
c.web_logs(log_type="nginx")             # access logs: IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_error_logs(log_type="apache")      # error logs: nginx/Apache/Tomcat/IIS HTTPERR
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")
c.syslog()                        # generic syslog, incl. auth.log/secure content
c.auditd_logs()                   # Linux Audit Framework
c.journal_logs()                  # systemd journal export
c.db_logs(log_type="mysql_slow")  # MySQL/MariaDB, PostgreSQL, MSSQL, Oracle logs
c.qcloud_logs(log_type="ydservice") # Tencent Cloud Host Security / YunJing logs
c.registry()                      # Windows Registry hives: SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/...
c.suspicious_registry()           # high-entropy values + Run/services/COM/IFEO persistence heuristics
c.suspicious_tasks()              # heuristic triage over scheduled_tasks
c.auth_events()                   # heuristic SSH/sudo/PAM/account triage over syslog
c.db.table("web_logs")            # generic escape hatch: any table this case has, by name

# Not sure what fields a table has, or which one to search on? fields()
# lists columns and JSON-catchall keys found in a bounded sample,
# with counts and example values; rare keys may be absent from the sample.
c.fields("events")       # -> Image, CommandLine, TargetUserName, ... (from event_data)

# No SQL required: exact/fuzzy/regex conditions against any table, AND/OR,
# case-insensitive by default. Refuses when estimated result size exceeds
# the memory budget; the estimate is not a hard process-memory guarantee.
c.search("web_logs", contains={"uri_stem": "admin"}, eq={"status": [401, 403]})
c.search("events", regex={"CommandLine": r".*-enc.*"})
for chunk in c.search_chunks("web_logs", contains={"uri_stem": "admin"}):
    process(chunk)
c.search_to_csv("web_logs", "admin_hits.csv", contains={"uri_stem": "admin"})

# Log-table accessors, query, search and timeline have "_chunks()" variants.
# Consume and discard each chunk; accumulating them recreates a full result.
# A chunk is bounded in rows, so wide records can still require substantial RAM.
for chunk in c.web_logs_chunks(log_type="nginx"):
    process(chunk)                # each chunk is a normal pandas.DataFrame
for chunk in c.query_chunks("SELECT * FROM web_error_logs WHERE severity = 'error'"):
    process(chunk)
```

## CLI reference

| Command | Purpose |
|---|---|
| `seclogx case init <name>` / `case list` / `case info <name>` | Manage case workspaces (`--dir` overrides the case root) |
| `seclogx ingest <case> --source PATH[:HOST]...` | Discover and normalize all supported log families (`--background` to run detached; `--staging-format auto/arrow/ndjson`) |
| `seclogx ingest-status <case> [job_id] [--watch]` | Check on a `--background` ingest job |
| `seclogx query <case> "<SQL>"` | Ad hoc SQL against any table in the case, streamed in bounded-memory chunks whether printing a preview or writing `--out` |
| `seclogx summary <case>` / `channels <case>` | Quick overview of the `events` (Windows Event Log) table |
| `seclogx sources <case>` | Row count per table (events, web_logs, web_error_logs, scheduled_tasks, exchange_message_tracking, exchange_logs, syslog, auditd_logs, journal_logs, db_logs, qcloud_logs, registry) |
| `seclogx table <case> <name>` | Preview any table or stream its rows to CSV with `--out` |
| `seclogx fields <case> <table>` | List columns and sampled JSON-catchall keys, with counts and example values |
| `seclogx search <case> <table> [--eq/--contains/--regex FIELD=VALUE]...` | Query any table without writing SQL: exact/fuzzy/regex conditions, case-insensitive by default, combined with AND (or `--match-any` for OR) |
| `seclogx tasks <case> [--suspicious]` | List ingested Scheduled Task definitions, optionally filtered by a built-in heuristic |
| `seclogx auth <case>` | List SSH/sudo/PAM/account-management events recognized in `syslog` (a heuristic view, not Sigma) |
| `seclogx registry <case> [--suspicious] [--hive-type TYPE]` | List ingested registry keys/values, optionally filtered to one hive type or the built-in persistence/entropy heuristics |
| `seclogx hunt <case> [--rules DIR] [--min-level LEVEL]` | Run Sigma rules, report matches + ATT&CK tags |
| `seclogx rules validate [--rules DIR]` | Check which rules convert vs are unsupported |
| `seclogx timeline <case> [--start/--end/--host/--channel/--event-id]` | Cross-host, filterable timeline over `events` |
| `seclogx worker` | Distributed-mode worker (opt-in, see below) |
| `seclogx cluster status/config` | Distributed-mode status/configuration |

Run any command with `--help` for full options.

## Development

```bash
conda activate python314
python -m pip install -e ".[dev]"
python -m pytest
```

`python -m pip install -e ".[cluster]"` in the same environment adds `redis`/`rq`/`boto3`, needed only for
distributed mode (`seclogx worker`, `seclogx cluster status`,
`SECLOGX_STORAGE_BACKEND=s3`) -- see
[10. Distributed deployment](docs/guides/10_distributed_deployment.md).

## License

MIT (see `LICENSE`) for seclogx's own code. Bundled Sigma rules under
`data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); see
`data/sigma_rules/SOURCES.md` for exact provenance per rule.
