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
  every other Exchange log type lands in a nothing-dropped catchall),
  **Linux** syslog (BSD/RFC-3164 and RFC 5424 -- `auth.log`/`secure`
  content included), the Linux Audit Framework (auditd), and systemd
  journal export logs, **database** logs (MySQL/MariaDB error/
  general/slow query logs, PostgreSQL, MSSQL, Oracle alert log), **Tencent
  Cloud Host Security** client text logs (YDService, HIDS/YDLive, scanners,
  YDFlame/YDUtils/YDQuaraV2, YDEyes), and **Windows Registry** hives (SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT,
  per-user NTUSER.DAT/UsrClass.dat). Each format is detected by content,
  not filename, so renamed/relocated evidence still works. See
  [02. Log types & schema](02_log_types_and_schema.md) for the full
  twelve-table picture.
- You get a `pandas.DataFrame`-native interface throughout (CLI
  tables/CSV, or a Python `Case` object for a notebook) plus built-in
  Sigma-rule threat hunting with MITRE ATT&CK tagging, covering both
  Windows Event Log and web access logs. **No SQL required either**:
  `seclogx search` / `Case.search()` filter any table with plain
  field/value conditions -- exact, fuzzy, or regex matching.
- Every parse error, unrecognized file, and unsupported rule is reported
  explicitly. Nothing is silently dropped.
- **Bounded memory at every step that touches the analyst directly.**
  Web access/error logs especially can reach terabyte scale across a
  case -- every DataFrame-returning method has a chunked/streamed
  alternative, and `search()` actively checks a result against the
  machine's available memory before fetching, refusing rather than
  risking a crash (see [03. Querying & search](03_querying_and_search.md)
  and [08. Performance & scale](08_performance_and_scale.md)).

It's designed for one workstation by default -- no distributed setup, no
external services required. Within that, realistic scale varies by log
family: EVTX cases are typically well under 100GB (comfortable for DuckDB
+ Parquet's lazy, out-of-core execution outright), while web access/error
logs can realistically reach terabyte scale, which is what the
bounded-memory delivery above is specifically for. An opt-in, purely
environment-variable-activated distributed mode also exists for large
ingest batches, large Sigma rule sets, or multiple analysts sharing one
case concurrently -- see
[10. Distributed deployment](10_distributed_deployment.md); it doesn't
change anything described above unless you turn it on.

## Installation

Requires Python 3.10+.

```bash
cd SecLogAnalyster
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run `seclogx` from inside this repo checkout (an editable install), since
the bundled Sigma rule set lives in `data/sigma_rules/` relative to the
repo root and is located at runtime from there.

Verify the install:

```bash
seclogx version
seclogx --help
```

## The case workspace

Everything revolves around a **case** -- a named workspace under
`./cases/<name>/` (override with `--case-root`) that holds:

```
cases/<name>/
  case.json                     # hosts, source paths, ingest run history
  staging/<host>/*.ndjson.gz       # intermediate parsed EVTX records, gzipped (kept by default)
  staging_aux/<host>/*.ndjson.gz   # intermediate parsed non-EVTX records, gzipped (kept by default)
  logs/ingest_<batch_id>.log    # reconciliation report per ingest run
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
`staging/`, `staging_aux/`, and `logs/` always stay local/NFS, in every
mode.

You create a case once (`seclogx case init`), then `ingest` into it as
many times as you like -- from different source paths, different hosts,
even weeks apart. Every ingest run is additive and recorded in
`case.json`. A single `ingest` run discovers and ingests every supported
format found under the source paths in one pass -- you don't ingest each
log type separately. A case only exposes the tables it actually has data
for; check with `seclogx sources <case>` / `Case.table_counts()`.

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
  the eleven tables holds and what to look for in it.
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
