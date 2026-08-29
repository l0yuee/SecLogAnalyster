# seclogx User Guide

**Language: English | [中文](user_guide.zh-CN.md)**

A practical, end-to-end guide to using seclogx for forensic log analysis
and threat hunting: Windows Event Log, on-disk Scheduled Task
definitions, IIS/nginx/Apache/Tomcat web access logs, and Exchange logs.
For internal design details, see `architecture.md`, `schema.md`,
`sigma_backend.md`, and `known_limitations.md` in this same folder.

## Table of contents

1. [What seclogx is for](#1-what-seclogx-is-for)
2. [Installation](#2-installation)
3. [Core concepts](#3-core-concepts)
4. [Command-line reference](#4-command-line-reference)
5. [Python / notebook API](#5-python--notebook-api)
6. [Analyst workflows / recipes](#6-analyst-workflows--recipes)
7. [Understanding hunt results and ATT&CK tags](#7-understanding-hunt-results-and-attck-tags)
8. [Extending detection: custom rules and fields](#8-extending-detection-custom-rules-and-fields)
9. [Performance and scale notes](#9-performance-and-scale-notes)
10. [Troubleshooting / FAQ](#10-troubleshooting--faq)
11. [Known limitations](#11-known-limitations)
12. [License and rule attribution](#12-license-and-rule-attribution)

---

## 1. What seclogx is for

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
  web application produces, including IIS HTTP.sys/HTTPERR), and
  **Exchange** CSV logs (Message Tracking gets first-class columns;
  every other Exchange log type lands in a nothing-dropped catchall).
  Each format is detected by content, not filename, so renamed/relocated
  evidence still works. See "Quick reference: analyzing each log type" in
  [section 3](#3-core-concepts) for the full six-table picture.
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
  risking a crash (see [section 5](#5-python--notebook-api) and
  [section 9](#9-performance-and-scale-notes)).

It's designed for one workstation, not a cluster -- no distributed setup,
no external services. Within that, realistic scale varies by log family:
EVTX cases are typically well under 100GB (comfortable for DuckDB +
Parquet's lazy, out-of-core execution outright), while web access/error
logs can realistically reach terabyte scale, which is what the
bounded-memory delivery above is specifically for.

## 2. Installation

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

## 3. Core concepts

### Case workspace

Everything revolves around a **case** -- a named workspace under
`./cases/<name>/` (override with `--case-root`) that holds:

```
cases/<name>/
  case.json                     # hosts, source paths, ingest run history
  staging/<host>/*.ndjson       # intermediate parsed EVTX records (kept by default)
  logs/ingest_<batch_id>.log    # reconciliation report per ingest run
  lake/
    events/host=<h>/channel=<c>/*.parquet                       # Windows Event Log
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat access logs
    web_error_logs/host=<h>/log_type=<t>/*.parquet               # nginx/Apache/Tomcat/IIS HTTPERR error logs
    scheduled_tasks/host=<h>/*.parquet                           # Task Scheduler definitions
    exchange_message_tracking/host=<h>/*.parquet                 # Exchange mail flow
    exchange_logs/host=<h>/log_type=<t>/*.parquet                # other Exchange CSV logs
```

You create a case once (`seclogx case init`), then `ingest` into it as
many times as you like -- from different source paths, different hosts,
even weeks apart. Every ingest run is additive and recorded in
`case.json`. A single `ingest` run discovers and ingests every supported
format found under the source paths in one pass -- you don't ingest each
log type separately. A case only exposes the tables it actually has data
for; check with `seclogx sources <case>` / `Case.table_counts()`.

### Normalized event schema

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

### The `event_data` field

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
search across it (see [section 6](#6-analyst-workflows--recipes)).

### The other tables: `web_logs`, `web_error_logs`, `scheduled_tasks`, `exchange_message_tracking`, `exchange_logs`

Windows Event Log isn't the only artifact `ingest` normalizes. Each of
these is fundamentally a different shape, so each gets its own table
rather than being crammed into `events` -- full column reference in
`docs/schema.md`. Every one of them is also reachable as a plain
`pandas.DataFrame` through a named `Case` accessor (`c.web_logs()`,
`c.scheduled_tasks()`, ...), the same first-class treatment `events` gets
via `summary()`/`hosts()`/`channels()` -- see
[section 5](#5-python--notebook-api).

| Table | What it holds | Key columns |
|---|---|---|
| `web_logs` | **Access logs**: IIS, nginx, Apache, and Tomcat HTTP access logs, unified | `log_type`, `client_ip`, `method`, `uri_stem`, `uri_query`, `status`, `user_agent`, `referer` |
| `web_error_logs` | **Error/diagnostic logs**: nginx, Apache, Tomcat, and IIS HTTP.sys (HTTPERR) -- the other major web-application log category, unified | `log_type`, `severity`, `client_ip`, `message`, plus IIS HTTPERR's `method`/`uri`/`status` |
| `scheduled_tasks` | On-disk Task Scheduler task definitions (`System32\Tasks\**`) -- a persistence artifact, distinct from the Task Scheduler *event log* (already in `events`) | `task_path`, `author`, `enabled`, `hidden`, `actions` (JSON), `triggers` (JSON) |
| `exchange_message_tracking` | Exchange mail flow (who sent what to whom) | `sender_address`, `recipient_address`, `message_subject`, `event_id` (Exchange's own, not a Windows Event ID) |
| `exchange_logs` | Every other Exchange CSV log type (HttpProxy, ActiveSync, EWS, ...), fields preserved verbatim | `log_type`, `fields` (JSON, query with `fields ->> 'field-name'`) |

A few things worth knowing before you query these:

- **Format is detected by content, not filename or extension** -- a live
  Task Scheduler task file has no extension at all, and forensic tools
  routinely rename exported logs. A file matching none of the supported
  formats is reported as unrecognized in the ingest summary, never
  silently skipped.
- **`web_logs` covers the access-log category; `web_error_logs` covers the
  error/diagnostic-log category** -- the two major log categories every
  web application produces. They're separate tables because they're
  structurally unrelated (access logs have a request/response shape;
  error logs are just severity + free text).
- **In `web_logs`, nginx vs. Apache vs. Tomcat is a best-effort label**,
  not a hard detection -- Common/Combined Log Format is byte-identical
  across all three; `log_type` falls back to `web_access` when no
  path/filename hint is available. IIS is always detected reliably
  (self-describing header).
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
- See [section 6](#6-analyst-workflows--recipes) for recipes, and
  `docs/known_limitations.md` for the full list of scope decisions.

### Quick reference: analyzing each log type

Every table below is always reachable the fully generic way regardless of
whether it has a dedicated interface: `seclogx query <case> "<SQL>"` /
`seclogx table <case> <name>` on the CLI, and `Case.query()`/
`Case.db.table(name)` (plus their `_chunks` siblings) in Python -- or,
if you'd rather not write SQL at all, `seclogx search <case> <table>` /
`Case.search()` (plain field/value conditions: exact, fuzzy, or regex
matching -- see the dedicated walkthrough right after this table). The
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

`seclogx sources <case>` isn't table-specific -- it's the one command to
run first, before any of the above: a row count per table so you know
what the case actually has before picking which of these to reach for.

What to actually look for in each, at a glance (full recipes in
[section 6](#6-analyst-workflows--recipes)):

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
  Public. `suspicious_tasks()` runs this heuristic for you.
- **`exchange_message_tracking`** -- phishing and mail-based
  exfiltration: sender/recipient/subject sweeps, unexpected external
  mail flow, a sender domain that doesn't match its claimed identity.
- **`exchange_logs`** -- Exchange HTTP-based compromise (e.g.
  ProxyShell-style attacks) where the relevant activity is in
  HttpProxy/OWA/ECP access patterns rather than mail flow -- sweep
  `fields` by content when you don't know the exact schema.

### Searching without SQL

Every SQL example elsewhere in this guide has a no-SQL equivalent:
`seclogx search <case> <table>` on the CLI, `Case.search()` in Python.
Conditions are plain field/value pairs, one of three kinds:

| Condition | Meaning | CLI flag | Python |
|---|---|---|---|
| Exact match | field equals a value exactly | `--eq FIELD=VALUE` | `eq={"field": "value"}` |
| Fuzzy match | field contains a value as a substring | `--contains FIELD=VALUE` | `contains={"field": "value"}` |
| Regular expression | field matches a regex pattern | `--regex FIELD=PATTERN` | `regex={"field": "pattern"}` |

```bash
# Find webshell-like hits: uri_stem contains "shell", status exactly 200
seclogx search incident42 web_logs --contains uri_stem=shell --eq status=200

# Same thing in Python
```
```python
from seclogx import Case
c = Case.open("incident42")
c.search("web_logs", contains={"uri_stem": "shell"}, eq={"status": 200})
```

A few things that make this more than "LIKE with extra steps":

- **Matching is case-insensitive by default** (`--case-sensitive` / 
  `case_sensitive=True` to opt into exact-case matching).
- **Multiple values on one condition combine with OR**: `--eq
  status=404,500` (CLI, comma-separated) or `eq={"status": ["404",
  "500"]}` (Python) matches either value.
- **Multiple different conditions combine with AND by default** (every
  condition must match), or OR with `--match-any` / `match="any"` (any
  one condition matching is enough).
- **Field names work whether or not they're a "real" column.** A field
  that isn't one of the table's own columns (`status`, `uri_stem`, ...) is
  looked up as a key inside the table's provider-specific JSON catchall
  (`event_data` for `events`, `extra` for `web_logs`/`web_error_logs`,
  `fields` for `exchange_logs`) automatically -- `Image`, `CommandLine`,
  `TargetUserName`, whatever the underlying provider actually calls it,
  just works:

  ```bash
  seclogx search incident42 events --contains Image=mimikatz --eq channel="Microsoft-Windows-Sysmon/Operational"
  seclogx search incident42 events --regex CommandLine=".*-enc.*"
  ```

  A field name that isn't a real column *and* doesn't resolve inside any
  JSON catchall (most fields on `scheduled_tasks`, which has none) is
  reported clearly, listing the table's actual columns, rather than a
  cryptic database error.
- **`--regex` uses regular expressions** (DuckDB's RE2-based engine --
  the same syntax most log-analysis tools use, no
  lookahead/lookbehind support, which log patterns rarely need anyway).
  `--contains` is always a literal substring, never a wildcard pattern --
  reach for `--regex` if you need real pattern matching.
- **It's memory-safe by design.** `search()` estimates the result size
  before fetching and refuses -- pointing you at the alternatives below --
  rather than risking your machine running out of memory:

  ```python
  from seclogx.errors import ResultTooLargeError
  try:
      df = c.search("web_logs", contains={"uri_stem": "shell"})
  except ResultTooLargeError as e:
      print(e)  # tells you roughly how big the result is and what to do instead
      for chunk in c.search_chunks("web_logs", contains={"uri_stem": "shell"}):
          ...                                    # process piece by piece, never all at once
      c.search_to_csv("web_logs", "hits.csv", contains={"uri_stem": "shell"})  # or just stream it to a file
  ```

  On the CLI this never turns into an error -- `seclogx search` always
  shows a bounded preview and tells you the estimated row/size count, and
  `--out` always streams every matching row to CSV regardless of size
  (see [section 9](#9-performance-and-scale-notes) for how the estimate
  itself works).

## 4. Command-line reference

Every command accepts `--case-root <dir>` (default `./cases`) to point
at a different case workspace location. Run any command with `--help`
for the full, current option list.

### `seclogx case init <name>`

Creates a new case workspace.

```bash
seclogx case init incident42
```

### `seclogx case list`

Lists all cases under `--dir` (default `./cases`).

### `seclogx case info <name>`

Prints the case's metadata as JSON: hosts ingested so far, and the
history of every ingest run (batch id, timestamps, file/record counts).

```bash
seclogx case info incident42
```

### `seclogx ingest <case> --source PATH[:HOST] [--source ...]`

Discovers, classifies, and normalizes every supported file under the
given source paths into the case in one pass: `.evtx`, Scheduled Task
definitions, IIS/nginx/Apache/Tomcat access logs, and Exchange CSV logs.
This is the core command.

| Option | Default | Meaning |
|---|---|---|
| `--source PATH[:HOST]` | required, repeatable | A file or directory to scan recursively. Optionally tag it with an explicit host label (`PATH:HOST`); if omitted, the source directory's own name is used as the host label. |
| `--workers N` | CPU count | Parallel staging workers. Files are parsed independently, so this scales with cores. |
| `--keep-raw` | off | `.evtx` sources only: also capture each record's raw XML into the lake (`raw_xml` column), for cases needing full evidentiary completeness. Roughly doubles ingest time and memory for the files it's applied to. |
| `--keep-staging` / `--no-keep-staging` | keep | Whether to keep the intermediate NDJSON under `staging/` after flattening (EVTX only -- the other formats don't stage to disk). Keeping it makes reprocessing cheap if you change something; deleting it saves disk. |
| `--case-root` | `./cases` | Where the case workspace lives. |

If `<case>` doesn't already exist, `ingest` creates it automatically. A
source with no `.evtx` files at all is not an error as long as it has at
least one supported non-EVTX artifact, or vice versa -- `ingest` only
fails if neither pass finds anything.

Examples:

```bash
# Single source, host label inferred from the directory name
seclogx ingest incident42 --source /evidence/wks01

# Multiple hosts from unrelated acquisition paths, explicit labels
seclogx ingest incident42 \
  --source /mnt/kape_output/WKS01:WKS01 \
  --source /mnt/kape_output/DC01:DC01 \
  --source /home/analyst/manual_copy/extra_logs:WKS01

# Keep raw XML for a small, high-value evidence set; use more workers
seclogx ingest incident42 --source /evidence/dc01:DC01 --keep-raw --workers 16
```

After every ingest run, seclogx prints a **reconciliation report**:
files discovered vs. staged OK vs. partially recovered vs. failed, and
staged records vs. rows actually written to the lake. Any file that
didn't parse cleanly is listed with its exact error and how many
records were recovered before the failure -- this report is also saved
to `cases/<name>/logs/ingest_<batch_id>.log`.

```
Ingest batch 66777433-... for case 'incident42'
  files discovered : 27
  files ok         : 25
  files partial    : 2  <-- some records lost mid-file, see per-file errors
  files failed     : 0
  records staged   : 101865
  records in lake  : 101865
  files with issues:
     /evidence/.../sysmon.evtx -- Failed to parse chunk header (358 recovered)
```

A `partial` file is not an error to panic over -- it means exactly what
it says: some number of records were successfully recovered before a
corrupted chunk stopped the rest of that file. Nothing before the
failure point is lost.

Right after the EVTX reconciliation report, a second one covers the
non-EVTX pass, with the same never-silently-drop philosophy -- files it
couldn't classify at all are called out explicitly rather than skipped:

```
Auxiliary log ingest (Scheduled Tasks / IIS / web access & error logs / Exchange):
  files discovered : 7
  files ok         : 6
  files partial    : 0
  files failed     : 0
  files unrecognized: 1  <-- content didn't match any supported format, not ingested
  rows written per table:
    exchange_message_tracking: 1
    scheduled_tasks: 1
    web_error_logs: 2
    web_logs: 4
  sample unrecognized files:
    /evidence/wks01/notes.txt
```

Also mirrored by `IngestReport.aux.to_dataframe()` (or `AuxIngestReport`
returned directly from `run_aux_ingest`), a per-file DataFrame just like
`IngestReport.to_dataframe()` gives you for the EVTX pass -- one row per
discovered file with its status, table, record/error counts.

### `seclogx query <case> "<SQL>"`

Runs arbitrary SQL against any table in the case (`events` or any of the
other log tables) and prints/exports the result. Results are streamed in
bounded-size chunks rather than fetched as one DataFrame first -- neither
the console preview nor `--out` requires the whole result to fit in
memory, which matters once you're querying a table at real-world web-log
volume (see [section 9](#9-performance-and-scale-notes)).

| Option | Meaning |
|---|---|
| `--out FILE.csv` | Stream the full result to CSV instead of printing a preview |
| `--limit N` | Cap the number of rows -- pushed into the query itself (`LIMIT`), not applied after fetching, so a limited query on a huge table doesn't pay to read more than it asked for |

```bash
seclogx query incident42 "
  SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
" --out process_creations.csv

# Export every 4xx/5xx web access log hit, however large the table --
# never held in memory as one DataFrame
seclogx query incident42 "SELECT * FROM web_logs WHERE status >= 400" --out web_errors.csv
```

### `seclogx summary <case>`

One row per `(host, channel, event_id)` with a count and first/last seen
timestamp for the `events` (Windows Event Log) table -- the fastest way
to see what's actually in a case's event log data.

### `seclogx channels <case>`

Lists every distinct channel present in the `events` table (useful for
discovering what log sources actually got captured, e.g. confirming
Sysmon was running).

### `seclogx sources <case>`

Row count per table currently in the case -- `events`, `web_logs`,
`web_error_logs`, `scheduled_tasks`, `exchange_message_tracking`,
`exchange_logs`, whichever are present. The quickest way to see what log
families a case actually has before writing queries against them.

```bash
seclogx sources incident42
```

### `seclogx table <case> <name>`

Full contents of any table this case has, as a DataFrame -- the CLI
counterpart to `Case.web_logs()`/`Case.scheduled_tasks()`/etc., useful for
tables that don't have their own dedicated command. Streamed in
bounded-size chunks, same as `query` above.

| Option | Meaning |
|---|---|
| `--out FILE.csv` | Stream the full result to CSV |
| `--limit N` | Cap the number of rows (pushed into the query) |

```bash
seclogx table incident42 web_error_logs
seclogx table incident42 exchange_message_tracking --out mailflow.csv
```

### `seclogx search <case> <table>`

Query any table without writing SQL -- see "Searching without SQL" in
[section 3](#3-core-concepts) for the full explanation of how conditions
and matching work. Always shows an estimated row/size count before
results; `--out` streams every matching row regardless of size, the
console preview only ever pulls a bounded number of rows.

| Option | Meaning |
|---|---|
| `--eq FIELD=VALUE` | Exact match. Comma-separate multiple values for OR (`status=404,500`). Repeatable. |
| `--contains FIELD=VALUE` | Fuzzy/substring match. Comma-separate for OR. Repeatable. |
| `--regex FIELD=PATTERN` | Regular-expression match (not comma-split -- one pattern per flag). Repeatable. |
| `--match-any` | Combine all conditions with OR instead of the default AND |
| `--case-sensitive` | Case-sensitive matching (default: case-insensitive) |
| `--out FILE.csv` | Stream every matching row to CSV instead of a preview |
| `--limit N` | Cap the number of rows (pushed into the query) |

```bash
# Possible webshell: uncommon extension, 200 status
seclogx search incident42 web_logs --contains uri_stem=.aspx --eq status=200

# Encoded PowerShell, case-insensitive by default
seclogx search incident42 events --regex CommandLine=".*-enc.*"

# Persistence hunting: hidden tasks OR ones invoking a LOLBin
seclogx search incident42 scheduled_tasks --eq hidden=true --match-any --contains actions=powershell

# Export every match to CSV regardless of how many rows that is
seclogx search incident42 web_error_logs --eq severity=error,SEVERE --out errors.csv
```

### `seclogx tasks <case> [--suspicious]`

Lists ingested Scheduled Task definitions from `scheduled_tasks`.

| Option | Meaning |
|---|---|
| `--suspicious` | Only tasks flagged by a built-in heuristic: action executable under a Temp/AppData/Public-like path, a LOLBin-style command (powershell/cmd/wscript/cscript/mshta/rundll32/regsvr32), a hidden task, or a task with no recorded author. Not a Sigma rule -- see [section 7](#7-understanding-hunt-results-and-attck-tags). |
| `--out FILE.csv` | Export the full result |

```bash
seclogx tasks incident42 --suspicious
```

### `seclogx hunt <case>`

Runs Sigma detection rules against the case and reports matches with
MITRE ATT&CK tags. Rules with `logsource.category: process_creation`,
`network_connection`, etc. run against `events`; `category: webserver`
rules run against `web_logs` instead. A rule whose target table has no
data in this case is reported as a failure ("case has no '&lt;table&gt;'
table ingested"), not silently skipped.

| Option | Default | Meaning |
|---|---|---|
| `--rules DIR` | bundled starter set | A directory of Sigma `.yml` rules to run instead of (or in addition to, if you merge directories yourself) the bundled ones. |
| `--min-level LEVEL` | none | Only run rules at or above this severity: `informational`, `low`, `medium`, `high`, `critical`. |
| `--out FILE.csv` | none | Write all matched event rows to CSV. |

```bash
seclogx hunt incident42
seclogx hunt incident42 --min-level high --out high_severity_matches.csv
seclogx hunt incident42 --rules ~/my-sigma-rules/
```

Output:

```
Hunt: 37 rules evaluated, 1 total matches
  rules skipped (unsupported logsource): 0
  rules failed (conversion/execution error): 0
  rules with matches:
    [high] HackTool - Mimikatz Execution -- 1 matches (ATT&CK: T1003.001, T1003.002, ...)
```

A hunt run **never silently drops a rule**: rules whose logsource
category isn't supported are reported under "skipped", and rules that
fail to convert to SQL or fail to execute are reported under "failed",
each with a reason. See [section 7](#7-understanding-hunt-results-and-attck-tags).

### `seclogx rules validate [--rules DIR]`

Checks which Sigma rules in a directory (default: the bundled set)
successfully convert to a DuckDB query, without running them against any
data. Useful after adding your own rules or field mappings.

```bash
seclogx rules validate --rules ~/my-sigma-rules/
```

### `seclogx timeline <case>`

A cross-host, time-sorted, filterable view -- the classic DFIR
"supertimeline", scoped to what you actually care about right now.
Streamed in bounded-size chunks, same as `query` above -- an unfiltered
or lightly-filtered timeline over a large case can still be far bigger
than comfortably fits in memory.

| Option | Meaning |
|---|---|
| `--start` / `--end` | ISO timestamp bounds |
| `--host` | Restrict to one host |
| `--channel` | Restrict to one channel |
| `--event-id` | Restrict to one or more event IDs (repeatable) |
| `--out FILE.csv` | Stream the full timeline to CSV |

```bash
# All 4624 (successful logon) events for one host, exported
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv

# Everything across all hosts in a specific window
seclogx timeline incident42 --start 2026-01-14T00:00:00 --end 2026-01-14T06:00:00
```

## 5. Python / notebook API

Everything the CLI does is available as a plain Python API, returning
`pandas.DataFrame` objects throughout -- built for dropping straight
into a Jupyter notebook alongside your usual pandas analysis.

```python
from seclogx import Case

# Create or open a case
c = Case.create("incident42")          # first time
c = Case.open("incident42")            # subsequent sessions

# Ingest (same semantics as the CLI; PATH or "PATH:HOST" strings)
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
)
print(report.summary_text())
report.to_dataframe()                  # per-file staging detail as a DataFrame (EVTX pass)
report.aux.to_dataframe()              # same, for the Scheduled Tasks/IIS/web/Exchange pass

# Explore
c.summary()
c.channels()
c.hosts()
c.table_counts()                       # DataFrame: table name -> row count, for every table this case has

# Ad hoc SQL -> DataFrame
df = c.query("""
    SELECT time_created, computer, (event_data ->> 'Image') AS image
    FROM events
    WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
""")

# ...or the same thing without SQL: plain field/value conditions against
# any table. eq= exact, contains= fuzzy/substring, regex= regular
# expression; case-insensitive by default; different conditions combine
# with AND (match="any" for OR); multiple values for one field combine
# with OR. Field names work whether or not they're a "real" column --
# Image/CommandLine/etc. are looked up inside event_data automatically.
# See "Searching without SQL" in section 3 for the full explanation.
df = c.search(
    "events",
    contains={"Image": "mimikatz"},
    eq={"channel": "Microsoft-Windows-Sysmon/Operational"},
)
c.search("web_logs", contains={"uri_stem": "admin"}, eq={"status": [401, 403]})
c.search("events", regex={"CommandLine": r".*-enc.*"})

# search() refuses (raising ResultTooLargeError) rather than risking an
# out-of-memory crash if the estimated result is too large -- see
# "Bounded-memory access for large tables" below for search_chunks()/
# search_to_csv(), the alternatives it points you at.

# Every log family is a first-class, DataFrame-returning accessor -- the
# same treatment `events` gets, so nothing requires raw SQL just to get a
# DataFrame. Each returns an empty (not erroring) DataFrame if the case
# has no data for it yet. See "Bounded-memory access for large tables"
# below before calling one of these unfiltered on a case with real-world
# web-log volume.
c.web_logs()                           # access logs: IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_logs(log_type="nginx")           # filtered to one engine
c.web_error_logs()                     # error logs: nginx/Apache/Tomcat/IIS HTTPERR
c.web_error_logs(log_type="apache")
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")

# The CaseDB convenience methods are available via c.db
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # full-text across event_data/provider/computer
c.db.tables                            # list[str]: which tables this case actually has
c.db.table("web_error_logs")           # generic escape hatch: any table by name, as a DataFrame

# Scheduled Task triage (heuristic, not Sigma -- see section 7)
c.suspicious_tasks()

# Hunt
results = c.hunt()                      # or c.hunt(rules_dir=Path("..."), min_level="high")
results.matches                         # DataFrame: matched event rows + sigma_rule_id/title/level/attack ids
results.rule_summary                    # DataFrame: one row per rule evaluated, with match counts
results.skipped                         # list[(path, reason)] for unsupported-logsource rules
results.failures                        # list[RuleFailure] for conversion/execution errors
results.save("matches.csv")

# Timeline
tl = c.timeline(host="WKS01", event_id=[4624, 4625])
```

### Bounded-memory access for large tables

Every DataFrame-returning accessor above -- `.query()`, `.table()`,
`.web_logs()`, `.timeline()`, all of them -- has a `_chunks` sibling that
returns an `Iterator[pd.DataFrame]` instead of one DataFrame. This
matters because `.query()`/`.table()`/etc. call DuckDB's `.fetchdf()`
under the hood, which materializes the *entire* result as one DataFrame:
fine for a filtered or aggregated result, but web access/error logs
especially can realistically reach terabyte scale across a case, well
past what fits in memory as one DataFrame -- DuckDB's lazy, out-of-core
*query execution* doesn't help once the last step pulls everything into
one object. The `_chunks` accessors use DuckDB's chunked fetch instead,
so memory use is bounded by `chunksize` (rows per chunk, default
100,000), not by how large the total result is. Verified empirically:
reading 5M rows via chunks added ~190MB of peak memory against ~2.7GB for
`fetchdf()` on the same query.

```python
from seclogx import Case
c = Case.open("incident42")

# Instead of this on a huge table (materializes everything at once):
# df = c.web_logs(log_type="nginx")

# ...iterate bounded-size chunks:
for chunk in c.web_logs_chunks(log_type="nginx"):
    # chunk is a normal pandas.DataFrame, just not the whole result
    suspicious = chunk[chunk["status"] >= 400]
    if not suspicious.empty:
        suspicious.to_csv("web_errors.csv", mode="a", header=False, index=False)

# Same pattern for any raw SQL, any table, and the timeline:
for chunk in c.query_chunks("SELECT * FROM web_error_logs WHERE severity IN ('error', 'SEVERE')"):
    ...
for chunk in c.db.table_chunks("exchange_message_tracking"):
    ...
for chunk in c.timeline_chunks(host="WKS01"):
    ...

# Tune chunksize (rows per chunk) if the default doesn't fit your row width:
for chunk in c.web_logs_chunks(chunksize=20_000):
    ...
```

Every `_chunks` accessor mirrors its eager counterpart's signature (same
filters, same `log_type=`/`host=`/etc. keywords) plus a `chunksize`
keyword, and yields nothing (not an error) if the case has no data for
that table -- consistent with the eager accessors returning an empty
DataFrame instead of raising.

The CLI applies this automatically: `seclogx query`/`table`/`tasks`/
`timeline` stream chunks straight to CSV for `--out`, and the console
preview only pulls enough rows to fill the table (never the whole
result) -- see [section 4](#4-command-line-reference). You don't need
`--chunks` or any equivalent flag; it's just how those commands work.

### `.search()`'s proactive memory-safety check

`.search()` goes one step further than the `_chunks` pattern above: it
estimates the result size *before* fetching (an exact `count(*)` times a
bytes-per-row figure from a small sample) and compares it against the
machine's actual currently-available memory. If materializing the whole
result as one DataFrame would use more than a quarter of that, it refuses
-- raising `ResultTooLargeError` -- instead of trying and risking an
out-of-memory crash:

```python
from seclogx.errors import ResultTooLargeError

try:
    df = c.search("web_logs", contains={"uri_stem": "shell"})
except ResultTooLargeError as e:
    print(e)
    # "this search matches an estimated 8,400,000 rows (~1200 MB) -- too
    #  large to safely hold in memory as one DataFrame. Use search_chunks()
    #  ... or search_to_csv() ..."

# The two alternatives it names, both memory-safe at any result size:
for chunk in c.search_chunks("web_logs", contains={"uri_stem": "shell"}):
    ...                                                          # iterate
c.search_to_csv("web_logs", "hits.csv", contains={"uri_stem": "shell"})  # or stream to a file
```

`query()`/`table()`/etc. don't do this estimate-and-refuse check
themselves (only `.search()` does) -- for those, reach for the `_chunks`
sibling yourself whenever you're not sure a result is small. If you
already know a `.search()` result will be small (a tightly-scoped
condition, say), you don't need to do anything differently -- the check
only ever blocks a fetch that's actually estimated too large; anything
that fits returns a normal DataFrame exactly like the eager accessors
above.

`Case` supports the context manager protocol to close its DuckDB
connection cleanly:

```python
with Case.open("incident42") as c:
    df = c.summary()
```

## 6. Analyst workflows / recipes

A handful of concrete, copy-pasteable starting points. All of these work
identically via `seclogx query <case> "<SQL>"` or `c.query("<SQL>")` in
Python. If you'd rather not write SQL at all, the first two are also
shown as `seclogx search` / `Case.search()` equivalents -- the same
pattern (condition dicts instead of a `WHERE` clause) applies to every
recipe below, and to every table, not just `events`.

**Find LOLBin abuse (process spawned by an unusual parent):**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND (event_data ->> 'Image') ILIKE '%\rundll32.exe'
ORDER BY time_created
```

No-SQL equivalent:

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --contains Image=rundll32.exe
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, contains={"Image": "rundll32.exe"})
```

**Encoded PowerShell:**

```sql
SELECT time_created, host, computer, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND ((event_data ->> 'CommandLine') ILIKE '%-enc%' OR (event_data ->> 'CommandLine') ILIKE '%-encodedcommand%')
ORDER BY time_created
```

No-SQL equivalent (`regex` covers both `-enc` and `-encodedcommand` in one condition):

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --regex CommandLine="-enc(odedcommand)?"
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, regex={"CommandLine": "-enc(odedcommand)?"})
```

**Successful logons by type, across all hosts (spot RDP/network logons of interest):**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'TargetUserName') AS user,
       (event_data ->> 'LogonType') AS logon_type,
       (event_data ->> 'IpAddress') AS src_ip
FROM events
WHERE channel = 'Security' AND event_id = 4624
ORDER BY time_created
```

**Sweep every ingested host for a known-bad indicator (hash, IP, domain, filename)
without knowing which field it'll be in:**

```bash
seclogx query incident42 "SELECT * FROM events WHERE event_data::VARCHAR ILIKE '%<indicator>%'"
```

or in Python: `c.db.search("<indicator>")`.

**Cross-host process-creation count, to spot an outlier host:**

```sql
SELECT host, count(*) AS n
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
GROUP BY host ORDER BY n DESC
```

**Build a parent/child process chain around a specific process on one host:**

```sql
SELECT time_created, event_id,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE host = 'WKS01' AND channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND time_created BETWEEN TIMESTAMP '2026-01-14 02:10:00' AND TIMESTAMP '2026-01-14 02:20:00'
ORDER BY time_created
```

**Run the bundled Sigma hunt, then drop straight into pandas for further
triage of just the high-severity hits:**

```python
from seclogx import Case
c = Case.open("incident42")
r = c.hunt(min_level="high")
r.matches[["time_created", "host", "sigma_rule_title", "sigma_attack_ids"]].sort_values("time_created")
```

**Web access log 4xx/5xx sweep, across IIS/nginx/Apache/Tomcat at once:**

```sql
SELECT host, log_type, time_created, client_ip, method, uri_stem, status
FROM web_logs
WHERE status >= 400
ORDER BY time_created
```

**Possible webshell activity (uncommon extension hit with a 200, or a
suspicious query string) in IIS/web logs:**

```sql
SELECT host, log_type, time_created, client_ip, uri_stem, uri_query, status
FROM web_logs
WHERE status = 200
  AND ((uri_stem) ILIKE '%.aspx' OR (uri_stem) ILIKE '%.jsp' OR (uri_stem) ILIKE '%.php')
  AND ((uri_query) ILIKE '%cmd=%' OR (uri_query) ILIKE '%eval%' OR (uri_query) ILIKE '%whoami%')
ORDER BY time_created
```

**High-severity entries across every web application's error log at once
(nginx `error`, Apache `error`, Tomcat `SEVERE`, ...):**

```sql
SELECT host, log_type, time_created, severity, message
FROM web_error_logs
WHERE severity IN ('error', 'SEVERE', 'crit', 'alert', 'emerg')
ORDER BY time_created
```

**IIS HTTP.sys (HTTPERR) rejections -- requests HTTP.sys itself refused
before they ever reached an IIS worker process (malformed requests,
queue limits, app pool issues); these never show up in `web_logs` at
all, which is exactly why `web_error_logs` is worth checking separately:**

```sql
SELECT host, time_created, client_ip, client_port, method, uri, status, message AS reason
FROM web_error_logs
WHERE log_type = 'iis_httperr'
ORDER BY time_created
```

**Exchange mail flow: everything sent by or to a suspect address:**

```sql
SELECT time_created, sender_address, recipient_address, message_subject, recipient_status
FROM exchange_message_tracking
WHERE (sender_address) ILIKE '%<suspect-domain-or-address>%'
   OR (recipient_address) ILIKE '%<suspect-domain-or-address>%'
ORDER BY time_created
```

**Any other Exchange log type (HttpProxy, EWS, ActiveSync, ...), swept by
field content without knowing the exact schema:**

```sql
SELECT host, log_type, time_created, fields
FROM exchange_logs
WHERE CAST(fields AS VARCHAR) ILIKE '%<indicator>%'
ORDER BY time_created
```

**Scheduled Tasks: everything not authored by a recognized account, or
hidden, or invoking a LOLBin -- the same heuristic `--suspicious` uses:**

```python
from seclogx import Case
c = Case.open("incident42")
c.suspicious_tasks()[["host", "task_path", "author", "hidden", "actions"]]
```

## 7. Understanding hunt results and ATT&CK tags

`seclogx hunt` runs every Sigma rule it can load and convert, and reports
three things:

- **Matches** (`results.matches`): the actual matched event rows, each
  tagged with `sigma_rule_id`, `sigma_rule_title`, `sigma_level`, and
  `sigma_attack_ids` (a comma-separated list of MITRE ATT&CK technique
  IDs, e.g. `T1003.001, T1003.002`).
- **Rule summary** (`results.rule_summary`): one row *per rule
  evaluated* (not per match) -- title, level, author, match count,
  ATT&CK tags, references. A rule with `matches == 0` simply didn't fire
  against this case's data; that's a normal, expected outcome for most
  rules most of the time.
- **Skipped / failed** (`results.skipped`, `results.failures`): rules
  that couldn't be loaded/routed (unsupported logsource category) or
  couldn't be converted/executed (unsupported Sigma feature, or a field
  this case's pipeline doesn't map yet). Always check these are empty or
  understood -- see `seclogx rules validate` and
  `docs/sigma_backend.md` if you need to extend field mappings.

ATT&CK technique names/tactics are enriched from a small bundled lookup
(`data/attack/techniques.json`) covering the techniques used by the
bundled rule set -- not the full ATT&CK framework. Unknown IDs still
show up as bare `TXXXX` identifiers.

The bundled rule set (37 rules, `data/sigma_rules/`) targets **Sysmon**
event fields specifically (process creation, network connections, file
events, registry changes, image loads, DNS queries, named pipes,
PowerShell script blocks, process access) -- it will only find things if
Sysmon was actually running and its logs were ingested. It is a curated
starting point, not exhaustive; see [section 8](#8-extending-detection-custom-rules-and-fields)
to add more.

`hunt` also supports Sigma's `category: webserver` rules (against
`web_logs`, i.e. **access** logs), for supplying your own IIS/nginx/Apache
webshell or exploitation-pattern rules -- none are bundled by default in
v1. There is no Sigma logsource category for on-disk Scheduled Task
definitions, web application **error** logs (`web_error_logs`), or
Exchange message tracking, so those aren't part of a Sigma hunt; use
`Case.suspicious_tasks()` / `seclogx tasks --suspicious` for tasks, and
plain SQL (section 6) for `web_error_logs` and Exchange.

## 8. Extending detection: custom rules and fields

Point `--rules` / `rules_dir=` at any directory of standard Sigma YAML
rules -- they don't have to come from the bundled set. Before relying on
a new rule set, run:

```bash
seclogx rules validate --rules /path/to/your/rules
```

This reports, per rule, whether it converts successfully. Common reasons
a rule won't convert out of the box:

- **It uses a Sigma field seclogx doesn't map yet.** Add it to
  `FIELD_MAPPING` in `src/seclogx/detect/pipeline.py` (see
  `docs/sigma_backend.md` for the exact pattern -- field expressions
  must be parenthesized).
- **It targets a logsource category seclogx doesn't route.** Add it to
  `LOGSOURCE_ROUTES` (if it targets `events`) or `LOGSOURCE_TABLE` (if it
  targets a different table, e.g. a new `web_logs`-backed category) in
  the same file.
- **It uses an unsupported Sigma feature** (case-sensitive `|cased`
  matching, numeric comparison modifiers, correlation rules) -- not
  supported in v1; see `docs/known_limitations.md`.

After changing the mapping, re-run `rules validate`, then `hunt` against
a case with data you expect to match, to confirm end to end.

## 9. Performance and scale notes

- Designed for one workstation, not a cluster -- there is no distributed
  mode. Within that, individual log families vary widely in realistic
  volume: EVTX cases are typically well under 100GB, while web access/
  error logs across a case can realistically reach terabyte scale.
- Ingest parallelism (`--workers`) scales with CPU cores -- files are
  parsed independently in separate processes.
- Querying and hunting run through DuckDB directly against the
  Hive-partitioned Parquet lake, which gives lazy, out-of-core execution
  with predicate pushdown: a query filtered to one host/channel/event
  range only reads the Parquet row groups it actually needs, not the
  whole lake into memory. That said, *fetching* a large unfiltered result
  still defaults to one in-memory DataFrame (`.query()`/`.table()`/
  `.web_logs()`/etc., via DuckDB's `fetchdf()`) -- for a table or query
  that isn't already filtered/aggregated down to something small, use the
  `_chunks` sibling instead (`.query_chunks()`, `.web_logs_chunks()`,
  `.timeline_chunks()`, ...), which bounds memory by `chunksize` rather
  than total result size. See "Bounded-memory access for large tables" in
  [section 5](#5-python--notebook-api) for the full explanation and a
  worked example; the CLI (`query`/`table`/`tasks`/`timeline`) uses this
  automatically for both `--out` and the console preview, so no CLI flag
  is needed to get the bounded-memory behavior there.
- `.search()` estimates a result's size before fetching it (`count(*)`,
  exact, plus a bytes-per-row figure from a small `LIMIT`-bounded sample,
  extrapolated to the full row count -- both steps bounded regardless of
  the table's total size, so the estimate itself never risks the memory
  it's trying to protect) and compares it against a quarter of the
  machine's actual currently-available memory, refusing rather than
  fetching if that's exceeded. Available memory is detected best-effort
  (`/proc/meminfo` on Linux, coarser fallbacks elsewhere) and falls back
  to a fixed 200MB assumption if it can't be determined at all, rather
  than assuming the machine has unlimited memory.
- `--keep-raw` roughly doubles ingest cost (time and peak memory) for
  the files it's applied to -- use it selectively on evidence that
  needs full XML fidelity, not by default on an entire large case.
- Scheduled Tasks/IIS/web access/Exchange logs are parsed straight to
  Python dicts per file (no intermediate NDJSON staging), and unlike the
  EVTX pipeline, **ingest for these log families is not yet
  bounded-memory**: a single ingest run accumulates every parsed row for
  a given table in memory across the whole batch before writing Parquet.
  Fine at the volumes exercised so far; a single ingest run processing
  enough files to reach terabyte scale *in one batch* could exhaust
  memory during ingest even though querying the resulting lake afterward
  would be fine. This is specifically an ingest-time boundary, separate
  from (and not fixed by) the query-side chunking above -- see
  `docs/known_limitations.md`.

## 10. Troubleshooting / FAQ

**"case '<name>' has no ingested data yet -- run `ingest` first"**
You created/opened a case but haven't successfully ingested anything
into it yet (or every source file failed to parse). Run `seclogx ingest`
and check the reconciliation report for errors.

**A query mentions a column that doesn't exist**
Provider-specific fields live inside `event_data`, not as top-level
columns -- use `event_data ->> 'FieldName'`, not `FieldName` directly.
See `docs/schema.md` for the full list of real top-level columns.

**A hunt reports rules under "failed"**
Run `seclogx rules validate --rules <dir>` against the same rules
directory to see the exact conversion/field-mapping error per rule, then
see [section 8](#8-extending-detection-custom-rules-and-fields).

**An ingest run shows files as `partial`**
Expected for corrupted `.evtx` files -- the parser recovers what it can
before the corruption point and reports exactly how many records that
was. Not a bug; see `docs/known_limitations.md`.

**`ingest` seems slow on a huge single file**
A single very large `.evtx` file isn't split across workers (parallelism
is per-file); `--workers` helps most when you have many files. Consider
whether `--keep-raw` is enabled unnecessarily, as it roughly doubles
per-file cost.

**I want to re-run ingest after fixing something**
Ingest is additive per run and safe to re-run; if you kept staging
(`--keep-staging`, the default), reprocessing existing NDJSON without
re-parsing the source `.evtx` is possible by calling the flatten step
directly (see `src/seclogx/ingest/flatten.py`) -- most users can simply
re-run `seclogx ingest` against the same sources.

**A file I expected to be ingested shows up under "files unrecognized"**
Its content didn't match any supported format's detection (see
`docs/known_limitations.md`). Common causes: a custom nginx/Apache
`log_format` that isn't Common/Combined Log Format, a truncated IIS/
Exchange header missing its `#Fields:` line, or a genuinely unsupported
file that happened to be under the source path. Check
`AuxIngestReport.unknown_samples` (or the ingest summary's sample list)
for the exact path.

**A web access log's `log_type` shows `web_access` instead of `nginx`/`apache`/`tomcat`**
Common/Combined Log Format is identical across all three servers; the
label is a best-effort path/filename heuristic, not a detection (see
`docs/known_limitations.md`). `web_access` just means no hint was found
-- the data itself is unaffected.

**`seclogx hunt` reports a rule as "case has no '&lt;table&gt;' table ingested"**
That rule's logsource category targets a table (`events` or `web_logs`)
this case hasn't ingested any data into yet -- not a conversion error.
Check `seclogx sources <case>` to see what the case actually has.

**A query against a large table (`web_logs` especially) uses too much memory or is slow to return**
`c.query()`/`c.table()`/`c.web_logs()`/etc. fetch the entire result as one
DataFrame. Switch to the `_chunks` sibling (`c.query_chunks()`,
`c.web_logs_chunks()`, ...) and iterate -- see "Bounded-memory access for
large tables" in [section 5](#5-python--notebook-api). If you're using
the CLI, `--out`/the console preview already use the chunked path
automatically; if it's still slow, check whether your query's `WHERE`
clause is actually selective (an unfiltered `SELECT * FROM web_logs`
still has to read the whole table, chunked or not -- chunking bounds
*memory*, not the amount of data scanned).

**`Case.search()` raised `ResultTooLargeError`**
Not a bug -- the estimated result was judged too large for this
machine's available memory to safely hold as one DataFrame. The error
message names the estimated row count/size; use `search_chunks()` to
iterate the same search in bounded-size pieces, or `search_to_csv()` to
stream every matching row straight to a file. On the CLI, `seclogx
search` never raises this -- it always shows a bounded preview and warns
in the same situation, telling you to add `--out` instead.

**`seclogx search` / `Case.search()` says a field "is not a column ... and this table has no JSON field to search inside either"**
The field name isn't one of the table's real columns, and the table has
no JSON-object catchall to look inside either (this only happens on
`scheduled_tasks` among the bundled tables -- see "Searching without
SQL" in [section 3](#3-core-concepts)). The error message lists the
table's actual column names. If you're trying to search inside
`actions`/`triggers` specifically, search that column directly with
`--contains`/`--regex` (whole-column text match) rather than a field name
nested inside it -- those are JSON *arrays*, not objects, so keyed
extraction doesn't apply.

## 11. Known limitations

Full details in `docs/known_limitations.md`. In short:

- `UserData`-based providers (some RDP/Task Scheduler/Defender events)
  are stored and full-text searchable, but not yet field-mapped for
  Sigma hunting the way `EventData`-based providers are.
- A very small number of records can have a `NULL` channel (a
  data-quality property of certain source files, handled gracefully).
- Sigma logsource categories route to their **Sysmon** equivalents, not
  native Security-channel equivalents (e.g. process creation -> Sysmon
  EventID 1, not Security 4688).
- Case-sensitive Sigma matching, numeric comparison modifiers, and
  correlation rules aren't supported.
- Sysinternals tools other than Sysmon (Procmon, Autoruns, ...) aren't
  ingested in v1.
- Non-EVTX format detection is content-based, not guaranteed --
  nonstandard log headers can be misclassified as unrecognized (reported,
  never silently dropped).
- Legacy `.job` (pre-Vista binary) Scheduled Tasks aren't parsed, only the
  modern Task Scheduler 2.0 XML format.
- nginx vs. Apache vs. Tomcat can't be reliably told apart from the log
  line alone in `web_logs` (byte-identical Common/Combined Log Format);
  the label is a path/filename heuristic. (In `web_error_logs`, the
  engine label *is* a real detection -- error-log format is
  engine-specific.)
- Only each web application's default/standard error-log format is
  recognized in `web_error_logs`; a customized format, or raw
  unstructured stdout mixed into Tomcat's `catalina.out`, produces
  reported parse errors rather than a misparse. A Tomcat entry's attached
  stack trace is capped at 200 continuation lines.
- FREB (IIS's XML-based per-request diagnostic trace) and Apache's
  `mod_rewrite`/SSL request logs aren't ingested in v1 -- only the
  standard access and error log categories.
- Only Exchange Message Tracking gets first-class columns; every other
  Exchange CSV log type lands in a generic `exchange_logs` catchall with
  fields preserved but not promoted to real columns.
- No Sigma logsource category exists for on-disk Scheduled Task
  definitions, web application error logs (`web_error_logs`), or Exchange
  logs, so hunting doesn't cover those tables.
- `.query()`/`.table()`/`.web_logs()`/etc. materialize the full result as
  one DataFrame; use the `_chunks` sibling for anything not already
  filtered/aggregated down to something small (see section 5/section 9).
- Ingest for the non-EVTX log families (Scheduled Tasks/IIS/web/Exchange)
  is not yet bounded-memory the way EVTX ingest and query/delivery are --
  a single ingest run holds every parsed row per table in memory across
  the whole batch before writing Parquet. Fine at the volumes exercised
  so far; a batch large enough to reach terabyte scale in one run could
  exhaust memory during ingest even though the resulting lake would query
  fine afterward.
- `seclogx search`/`Case.search()`'s `equals` always compares a value's
  *text* representation (so it doesn't matter whether the underlying
  column is numeric); `contains` is a literal, escaped substring search,
  never a wildcard pattern (use `regex` for that); `regex` uses DuckDB's
  RE2-based engine (no lookahead/lookbehind).
- A field that resolves into a JSON *array* column
  (`scheduled_tasks.actions`/`triggers`) can't be searched by key --
  search that column directly (whole-column text match) instead.
- The memory-safety estimate behind `.search()`'s refusal is a
  `count(*)` (exact) times a sampled bytes-per-row figure (extrapolated,
  not exact) -- a result with unusually wide row-to-row size variance can
  be estimated somewhat off in either direction; the default safety
  margin (a quarter of available memory) is deliberately conservative to
  absorb this.

## 12. License and rule attribution

seclogx's own code is MIT licensed (`LICENSE`). The bundled Sigma rules
under `data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); exact
upstream source and commit per rule is recorded in
`data/sigma_rules/SOURCES.md`, and every match reports the original
rule's author.
