# seclogx User Guide

**Language: English | [中文](user_guide.zh-CN.md)**

A practical, end-to-end guide to using seclogx for Windows Event Log
analysis and threat hunting. For internal design details, see
`architecture.md`, `schema.md`, `sigma_backend.md`, and
`known_limitations.md` in this same folder.

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
- You get a `pandas.DataFrame`-native interface (CLI tables/CSV, or a
  Python `Case` object for a notebook) plus built-in Sigma-rule threat
  hunting with MITRE ATT&CK tagging.
- Every parse error and unsupported rule is reported explicitly. Nothing
  is silently dropped.

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
  staging/<host>/*.ndjson       # intermediate parsed records (kept by default)
  logs/ingest_<batch_id>.log    # reconciliation report per ingest run
  lake/host=<h>/channel=<c>/*.parquet   # the normalized, queryable data
```

You create a case once (`seclogx case init`), then `ingest` into it as
many times as you like -- from different source paths, different hosts,
even weeks apart. Every ingest run is additive and recorded in
`case.json`.

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

Parses and normalizes `.evtx` files into the case. This is the core
command.

| Option | Default | Meaning |
|---|---|---|
| `--source PATH[:HOST]` | required, repeatable | A file or directory to scan recursively for `.evtx`. Optionally tag it with an explicit host label (`PATH:HOST`); if omitted, the source directory's own name is used as the host label. |
| `--workers N` | CPU count | Parallel staging workers. Files are parsed independently, so this scales with cores. |
| `--keep-raw` | off | Also capture each record's raw XML into the lake (`raw_xml` column), for cases needing full evidentiary completeness. Roughly doubles ingest time and memory for the files it's applied to. |
| `--keep-staging` / `--no-keep-staging` | keep | Whether to keep the intermediate NDJSON under `staging/` after flattening. Keeping it makes reprocessing cheap if you change something; deleting it saves disk. |
| `--case-root` | `./cases` | Where the case workspace lives. |

If `<case>` doesn't already exist, `ingest` creates it automatically.

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
timestamp -- the fastest way to see what's actually in a case.

### `seclogx channels <case>`

Lists every distinct channel present in the case (useful for discovering
what log sources actually got captured, e.g. confirming Sysmon was
running).

### `seclogx hunt <case>`

Runs Sigma detection rules against the case and reports matches with
MITRE ATT&CK tags.

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

# Ad hoc SQL -> DataFrame
df = c.query("""
    SELECT time_created, computer, (event_data ->> 'Image') AS image
    FROM events
    WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
""")

# The CaseDB convenience methods are available via c.db
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # full-text across event_data/provider/computer

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
  `LOGSOURCE_ROUTES` in the same file.
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

## 12. License and rule attribution

seclogx's own code is MIT licensed (`LICENSE`). The bundled Sigma rules
under `data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); exact
upstream source and commit per rule is recorded in
`data/sigma_rules/SOURCES.md`, and every match reports the original
rule's author.
