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
  Task** definitions (a persistence artifact), **IIS** W3C access logs,
  **nginx/Apache/Tomcat** access logs, and **Exchange** CSV logs
  (Message Tracking gets first-class columns; every other Exchange log
  type lands in a nothing-dropped catchall). Each format is detected by
  content, not filename, so renamed/relocated evidence still works.
- You get a `pandas.DataFrame`-native interface (CLI tables/CSV, or a
  Python `Case` object for a notebook) plus built-in Sigma-rule threat
  hunting with MITRE ATT&CK tagging, covering both Windows Event Log and
  web access logs.
- Every parse error, unrecognized file, and unsupported rule is reported
  explicitly. Nothing is silently dropped.

It's designed for realistic single-analyst case volumes (well under
100GB) on one workstation -- no cluster, no external services.

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
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat
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

### The other tables: `web_logs`, `scheduled_tasks`, `exchange_message_tracking`, `exchange_logs`

Windows Event Log isn't the only artifact `ingest` normalizes. Each of
these is fundamentally a different shape, so each gets its own table
rather than being crammed into `events` -- full column reference in
`docs/schema.md`.

| Table | What it holds | Key columns |
|---|---|---|
| `web_logs` | IIS, nginx, Apache, and Tomcat HTTP access logs, unified | `log_type`, `client_ip`, `method`, `uri_stem`, `uri_query`, `status`, `user_agent`, `referer` |
| `scheduled_tasks` | On-disk Task Scheduler task definitions (`System32\Tasks\**`) -- a persistence artifact, distinct from the Task Scheduler *event log* (already in `events`) | `task_path`, `author`, `enabled`, `hidden`, `actions` (JSON), `triggers` (JSON) |
| `exchange_message_tracking` | Exchange mail flow (who sent what to whom) | `sender_address`, `recipient_address`, `message_subject`, `event_id` (Exchange's own, not a Windows Event ID) |
| `exchange_logs` | Every other Exchange CSV log type (HttpProxy, ActiveSync, EWS, ...), fields preserved verbatim | `log_type`, `fields` (JSON, query with `fields ->> 'field-name'`) |

A few things worth knowing before you query these:

- **Format is detected by content, not filename or extension** -- a live
  Task Scheduler task file has no extension at all, and forensic tools
  routinely rename exported logs. A file matching none of the supported
  formats is reported as unrecognized in the ingest summary, never
  silently skipped.
- **nginx vs. Apache vs. Tomcat is a best-effort label**, not a hard
  detection -- Common/Combined Log Format is byte-identical across all
  three; `log_type` falls back to `web_access` when no path/filename hint
  is available. IIS is always detected reliably (self-describing header).
- **Exchange support is scoped to Message Tracking as first-class
  columns**; every other Exchange log type (there are over a dozen)
  lands in `exchange_logs` with all fields preserved in `fields`, still
  fully queryable, just not promoted to real columns.
- See [section 6](#6-analyst-workflows--recipes) for recipes, and
  `docs/known_limitations.md` for the full list of scope decisions.

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
Auxiliary log ingest (Scheduled Tasks / IIS / web access / Exchange):
  files discovered : 6
  files ok         : 5
  files partial    : 0
  files failed     : 0
  files unrecognized: 1  <-- content didn't match any supported format, not ingested
  rows written per table:
    exchange_message_tracking: 1
    scheduled_tasks: 1
    web_logs: 4
  sample unrecognized files:
    /evidence/wks01/notes.txt
```

### `seclogx query <case> "<SQL>"`

Runs arbitrary SQL against the case's `events` view (the whole
normalized lake) and prints/exports the result.

| Option | Meaning |
|---|---|
| `--out FILE.csv` | Write the full result to CSV instead of printing a table |
| `--limit N` | Cap the number of rows |

```bash
seclogx query incident42 "
  SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
" --out process_creations.csv
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
`scheduled_tasks`, `exchange_message_tracking`, `exchange_logs`,
whichever are present. The quickest way to see what log families a case
actually has before writing queries against them.

```bash
seclogx sources incident42
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

| Option | Meaning |
|---|---|
| `--start` / `--end` | ISO timestamp bounds |
| `--host` | Restrict to one host |
| `--channel` | Restrict to one channel |
| `--event-id` | Restrict to one or more event IDs (repeatable) |
| `--out FILE.csv` | Export the full timeline |

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
report.to_dataframe()                  # per-file staging detail as a DataFrame

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
web = c.query("SELECT * FROM web_logs WHERE status >= 400 ORDER BY time_created")

# The CaseDB convenience methods are available via c.db
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # full-text across event_data/provider/computer
c.db.tables                            # list[str]: which tables this case actually has

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

`Case` supports the context manager protocol to close its DuckDB
connection cleanly:

```python
with Case.open("incident42") as c:
    df = c.summary()
```

## 6. Analyst workflows / recipes

A handful of concrete, copy-pasteable starting points. All of these work
identically via `seclogx query <case> "<SQL>"` or `c.query("<SQL>")` in
Python.

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

**Encoded PowerShell:**

```sql
SELECT time_created, host, computer, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND ((event_data ->> 'CommandLine') ILIKE '%-enc%' OR (event_data ->> 'CommandLine') ILIKE '%-encodedcommand%')
ORDER BY time_created
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
`web_logs`), for supplying your own IIS/nginx/Apache webshell or
exploitation-pattern rules -- none are bundled by default in v1. There is
no Sigma logsource category for on-disk Scheduled Task definitions or
Exchange message tracking, so those aren't part of a Sigma hunt; use
`Case.suspicious_tasks()` / `seclogx tasks --suspicious` for tasks, and
plain SQL (section 6) for Exchange.

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

- Designed and tested for realistic single-case volumes well under
  100GB, on one workstation. There is no distributed/cluster mode.
- Ingest parallelism (`--workers`) scales with CPU cores -- files are
  parsed independently in separate processes.
- Querying and hunting run through DuckDB directly against the
  Hive-partitioned Parquet lake (`lake/host=.../channel=.../*.parquet`),
  which gives lazy, out-of-core execution with predicate pushdown: a
  query filtered to one host/channel/event range only reads the Parquet
  row groups it actually needs, not the whole lake into memory.
- `--keep-raw` roughly doubles ingest cost (time and peak memory) for
  the files it's applied to -- use it selectively on evidence that
  needs full XML fidelity, not by default on an entire large case.
- Scheduled Tasks/IIS/web access/Exchange logs are parsed straight to
  Python dicts per file (no intermediate NDJSON staging) -- appropriate
  at their typical per-file record volume, which is far lower than
  EVTX's. Parallelism is still per-file via the same `--workers` setting.

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
  line alone (byte-identical Common/Combined Log Format); the label is a
  path/filename heuristic.
- Only Exchange Message Tracking gets first-class columns; every other
  Exchange CSV log type lands in a generic `exchange_logs` catchall with
  fields preserved but not promoted to real columns.
- No Sigma logsource category exists for on-disk Scheduled Task
  definitions or Exchange logs, so hunting doesn't cover those tables.

## 12. License and rule attribution

seclogx's own code is MIT licensed (`LICENSE`). The bundled Sigma rules
under `data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); exact
upstream source and commit per rule is recorded in
`data/sigma_rules/SOURCES.md`, and every match reports the original
rule's author.
