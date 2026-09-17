# 1. Getting started

**Language: English | [中文](01_getting_started.zh-CN.md)**

**[Guide index](../index.md)** -- 01. Getting started | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

## What seclogx is for

Forensic acquisitions produce Windows Event Log (`.evtx`) files that are
painful to work with directly: a binary format, verbose XML once
extracted, and wildly inconsistent fields across the hundreds of
providers that write to it. Pushing them into a SIEM like ELK for
one-off case analysis is often worse -- brittle index mappings silently
drop fields you needed.

seclogx exists to make the first hours of triage fast:

- Point it at one or more forensic acquisition directories (they don't
  need to be under one parent folder, and can come from different
  hosts).
- It parses **every** `.evtx` channel generically -- Security, System,
  Application, Sysmon Operational, PowerShell Operational,
  WMI-Activity, and anything else -- into one normalized, queryable
  table.
- It also discovers and normalizes, in the same pass: on-disk **Scheduled
  Task** definitions (a persistence artifact), **IIS/nginx/Apache/Tomcat**
  access logs *and* error/diagnostic logs (both major log categories a
  web application produces, including IIS HTTP.sys/HTTPERR),
  **Exchange** CSV logs (Message Tracking gets first-class columns;
  other recognized Exchange CSV types retain their fields in a generic table),
  **Linux** syslog (BSD/RFC-3164 and RFC 5424 -- `auth.log`/`secure`
  content included), the Linux Audit Framework (auditd), and systemd
  journal export logs, **database** logs (MySQL/MariaDB error/
  general/slow query logs, PostgreSQL, MSSQL, Oracle alert log), **Tencent
  Cloud Host Security** client text logs (YDService, HIDS/YDLive, scanners,
  YDFlame/YDUtils/YDQuaraV2, YDEyes), and **Windows Registry** hives (SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT,
  per-user NTUSER.DAT/UsrClass.dat). EVTX discovery uses the `.evtx` suffix;
  auxiliary candidates are classified from a bounded content prefix, with
  suffix exclusions and some format-specific filename/path hints. Renaming
  evidence can therefore affect detection. See
  [02. Log types & schema](02_log_types_and_schema.md) for the full
  twelve-table picture.
- You get DataFrames and chunk iterators through a Python `Case` object,
  plus CLI previews/CSV export and built-in
  Sigma-rule threat hunting with MITRE ATT&CK tagging, covering both
  Windows Event Log and web access logs. **No SQL required either**:
  `seclogx search` / `Case.search()` filter any table with plain
  field/value conditions -- exact, fuzzy, or regex matching.
- Reconciliation reports identify discovered files that parsed partially,
  failed, or could not be classified; unsupported rules are also reported.
  Known unrelated suffixes and empty auxiliary files are filtered, and
  inaccessible paths may be skipped. This is not a complete acquisition inventory.
- **Chunked access for large log tables.** Log-table accessors, SQL queries,
  search and timelines offer streaming alternatives; `search()` estimates
  result size before fetching. Ordinary DataFrame methods and derived analyses
  can still exhaust memory. Consume chunks one at a time rather than retaining
  all of them (see [03. Querying & search](03_querying_and_search.md)
  and [08. Performance & scale](08_performance_and_scale.md)).

It's designed for one workstation by default, with no external services
required. Import time and disk/memory requirements depend on the log formats,
record widths, parallelism and storage. Chunked delivery avoids materializing
the whole query result but does not bound every operation's memory. An opt-in, purely
environment-variable-activated distributed mode also exists for large
ingest batches, large Sigma rule sets, or multiple analysts sharing one
case concurrently -- see
[10. Distributed deployment](10_distributed_deployment.md); it doesn't
change anything described above unless you turn it on.

## Installation

The package requires Python 3.10+. Work on this checkout uses the dedicated
conda **`python314`** environment, isolated from `base`.

```bash
cd SecLogAnalyster
conda activate python314
python -m pip install -e .
```

Run `seclogx` from inside this repo checkout (an editable install), since
the bundled Sigma rule set lives in `data/sigma_rules/` relative to the
repo root and is located at runtime from there.

Use this environment for tests and scripts as well. Where activation is not
available, run `conda run --no-capture-output -n python314 python ...`.
With JupyterLab and `ipykernel` installed there, launch `python -m jupyterlab` and select
the `python314` kernel; verify its interpreter with `sys.executable`.
If needed, register the installed kernel with
`python -m ipykernel install --user --name python314 --display-name "Python (python314)"`.

Verify the install:

```bash
seclogx version
seclogx --help
```

## The case workspace

Everything revolves around a **case** -- a named workspace under
`./cases/<name>/` (`case init/list/info` use `--dir`; ingest/query commands use
`--case-root`) that holds:

```
cases/<name>/
  case.json                         # hosts and ingest run history
  staging/<batch_id>/<host>/*.ndjson.gz       # EVTX staging shards (kept by default)
  staging_aux/<batch_id>/<host>/*.{ndjson.gz,arrow}  # auxiliary staging shards (kept by default)
  logs/ingest_<batch_id>.log          # EVTX reconciliation report
  jobs/<job_id>.json                 # background status snapshot
  jobs/<job_id>.log                  # background stdout/stderr and reports
  lake/
    events/host=<h>/channel=<c>/*.parquet                       # Windows Event Log
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat access logs
    web_error_logs/host=<h>/log_type=<t>/*.parquet               # nginx/Apache/Tomcat/IIS HTTPERR error logs
    scheduled_tasks/host=<h>/*.parquet                           # Task Scheduler definitions
    exchange_message_tracking/host=<h>/*.parquet                 # Exchange mail flow
    exchange_logs/host=<h>/log_type=<t>/*.parquet                # other Exchange CSV logs
    syslog/host=<h>/*.parquet                                    # generic syslog, incl. auth.log/secure
    auditd_logs/host=<h>/record_type=<r>/*.parquet                # Linux Audit Framework
    journal_logs/host=<h>/*.parquet                              # systemd journal export
    db_logs/host=<h>/log_type=<t>/*.parquet                       # MySQL/PostgreSQL/MSSQL/Oracle logs
    qcloud_logs/host=<h>/log_type=<t>/*.parquet                   # Tencent Cloud Host Security client logs
    registry/host=<h>/hive_type=<t>/*.parquet                     # Windows Registry hives
```

`lake/` can live on S3-compatible object storage instead of local disk
(`SECLOGX_STORAGE_BACKEND=s3` -- opt-in, see
[10. Distributed deployment](10_distributed_deployment.md)); `case.json`,
`staging/`, `staging_aux/`, `logs/`, and `jobs/` always stay local/NFS, in every
mode.

You create a case once (`seclogx case init`), then `ingest` into it as
many times as you like -- from different source paths, different hosts,
even weeks apart. Every ingest run is additive and recorded in
`case.json`. A single `ingest` run discovers and ingests every supported
format found under the source paths in one pass -- you don't ingest each
log type separately. A case only exposes the tables it actually has data
for; check with `seclogx sources <case>` / `Case.table_counts()`.

Imports are additive, without cross-run deduplication or checkpoint/resume.
Overlapping source paths are deduplicated within one scan, but running the same
import twice appends duplicate rows. Each pipeline stages its batch before
conversion; retained staging is not a resumable checkpoint, and deleting it
after conversion does not eliminate peak disk use. Background ingest does not
guarantee consistent queries while files are still being written. Wait for
completion, review the report and reopen the Case before analysis.

Auxiliary staging defaults to `auto`: sources of at least 16 MiB use Arrow IPC
with ZSTD level 1, smaller files use gzip NDJSON. EVTX always uses NDJSON.
The CLI accepts `--staging-format auto|arrow|ndjson`; Python uses
`IngestOptions(staging_format="auto")`. Auxiliary Parquet uses ZSTD level 1.
Memory/thread budgets and batch sizes are documented in the
[CLI reference](05_cli_reference.md) and [Notebook API](06_python_api.md).

## Quickstart

```bash
seclogx case init incident42
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx sources incident42
seclogx fields incident42 events
seclogx search incident42 events --contains Image=mimikatz --eq host=WKS01
seclogx hunt incident42
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

Where to go next:

- **[02. Log types & schema](02_log_types_and_schema.md)** -- what each of
  the twelve tables holds and what to look for in it.
- **[03. Querying & search](03_querying_and_search.md)** -- SQL, the
  no-SQL `search()` interface, and bounded-memory delivery.
- **[04. Threat hunting](04_threat_hunting.md)** -- Sigma rules and ATT&CK
  tagging.
- **[05. CLI reference](05_cli_reference.md)** / **[06. Python API](06_python_api.md)**
  -- the full command/method reference.
- **[07. Recipes](07_recipes.md)** -- copy-pasteable starting points.

## License and rule attribution

seclogx's own code is MIT licensed (`LICENSE`). The bundled Sigma rules
under `data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); exact
upstream source and commit per rule is recorded in
`data/sigma_rules/SOURCES.md`, and every match reports the original
rule's authorship. See the repo root `README.md` for the full license
text and pointers.
