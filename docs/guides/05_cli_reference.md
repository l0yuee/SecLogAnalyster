# 5. CLI reference

**Language: English | [中文](05_cli_reference.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | 05. CLI reference | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

Every command accepts `--case-root <dir>` (default `./cases`) to point
at a different case workspace location. Run any command with `--help`
for the full, current option list.

## `seclogx case init <name>`

Creates a new case workspace.

```bash
seclogx case init incident42
```

## `seclogx case list`

Lists all cases under `--dir` (default `./cases`).

## `seclogx case info <name>`

Prints the case's metadata as JSON: hosts ingested so far, and the
history of every ingest run (batch id, timestamps, file/record counts).

```bash
seclogx case info incident42
```

## `seclogx ingest <case> --source PATH[:HOST] [--source ...]`

Discovers, classifies, and normalizes every supported file under the
given source paths into the case in one pass: `.evtx`, Scheduled Task
definitions, IIS/nginx/Apache/Tomcat access logs, Exchange CSV logs,
Linux syslog/`auth.log`, auditd, and systemd journal export logs, and
MySQL/MariaDB/PostgreSQL/MSSQL/Oracle database logs. This is the core
command.

| Option | Default | Meaning |
|---|---|---|
| `--source PATH[:HOST]` | required, repeatable | A file or directory to scan recursively. Optionally tag it with an explicit host label (`PATH:HOST`); if omitted, the source directory's own name is used as the host label. |
| `--workers N` | CPU count | Parallel staging workers. Files are parsed independently, so this scales with cores. |
| `--keep-raw` | off | `.evtx` sources only: also capture each record's raw XML into the lake (`raw_xml` column), for cases needing full evidentiary completeness. Roughly doubles ingest time and memory for the files it's applied to. |
| `--keep-staging` / `--no-keep-staging` | keep | Whether to keep the intermediate NDJSON after flattening -- `staging/` for `.evtx` sources, `staging_aux/` for every other log family. Keeping it makes reprocessing cheap if you change something; deleting it saves disk. |
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

## `seclogx query <case> "<SQL>"`

Runs arbitrary SQL against any table in the case (`events` or any of the
other log tables) and prints/exports the result. Results are streamed in
bounded-size chunks rather than fetched as one DataFrame first -- neither
the console preview nor `--out` requires the whole result to fit in
memory, which matters once you're querying a table at real-world web-log
volume (see [08. Performance & scale](08_performance_and_scale.md)).

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

## `seclogx summary <case>`

One row per `(host, channel, event_id)` with a count and first/last seen
timestamp for the `events` (Windows Event Log) table -- the fastest way
to see what's actually in a case's event log data.

## `seclogx channels <case>`

Lists every distinct channel present in the `events` table (useful for
discovering what log sources actually got captured, e.g. confirming
Sysmon was running).

## `seclogx sources <case>`

Row count per table currently in the case -- `events`, `web_logs`,
`web_error_logs`, `scheduled_tasks`, `exchange_message_tracking`,
`exchange_logs`, `syslog`, `auditd_logs`, `journal_logs`, `db_logs`,
whichever are present. The quickest way to see what log families a case
actually has before writing queries against them.

```bash
seclogx sources incident42
```

## `seclogx table <case> <name>`

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

## `seclogx fields <case> <table>`

What can I search on? Lists every field this case's real, ingested data
has for a table -- see "Which fields can I search on?" in
[02. Log types & schema](02_log_types_and_schema.md). Computed from a
bounded sample, so it's safe to run against a table of any size.

| Option | Meaning |
|---|---|
| `--sample-size N` | How many rows to sample (default 5000) |

```bash
seclogx fields incident42 events
seclogx fields incident42 web_logs --sample-size 20000
```

## `seclogx search <case> <table>`

Query any table without writing SQL -- see
[03. Querying & search](03_querying_and_search.md) for the full
explanation of how conditions and matching work. Always shows an
estimated row/size count before results; `--out` streams every matching
row regardless of size, the console preview only ever pulls a bounded
number of rows.

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

## `seclogx tasks <case> [--suspicious]`

Lists ingested Scheduled Task definitions from `scheduled_tasks`.

| Option | Meaning |
|---|---|
| `--suspicious` | Only tasks flagged by a built-in heuristic (action path under Temp/AppData/Public, a LOLBin-style command, hidden, no recorded author, or masquerading as a known Microsoft task -- see "The other tables" in [02. Log types & schema](02_log_types_and_schema.md) for the full list and the `suspicion_reasons` column that explains each match). Not a Sigma rule -- see [04. Threat hunting](04_threat_hunting.md). |
| `--out FILE.csv` | Export the full result |

```bash
seclogx tasks incident42 --suspicious
```

## `seclogx auth <case>`

Lists `syslog` rows recognized as SSH/sudo/PAM/account-management events
(see `Case.auth_events()` / [02. Log types & schema](02_log_types_and_schema.md)
for exactly what's recognized). Not a Sigma rule -- a heuristic filter over
already-ingested `syslog` data, the `auth.log`/`secure` equivalent of
`tasks --suspicious`.

| Option | Meaning |
|---|---|
| `--out FILE.csv` | Export the full result |

```bash
seclogx auth incident42
seclogx auth incident42 --out auth_events.csv
```

## `seclogx hunt <case>`

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
each with a reason. See [04. Threat hunting](04_threat_hunting.md).

## `seclogx rules validate [--rules DIR]`

Checks which Sigma rules in a directory (default: the bundled set)
successfully convert to a DuckDB query, without running them against any
data. Useful after adding your own rules or field mappings.

```bash
seclogx rules validate --rules ~/my-sigma-rules/
```

## `seclogx timeline <case>`

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

## `seclogx worker`

Runs a distributed-mode worker: consumes ingest/hunt tasks enqueued by
`seclogx ingest`/`seclogx hunt` once `SECLOGX_BROKER_URL` is set. See
[10. Distributed deployment](10_distributed_deployment.md) for the full
env-var reference and Docker Compose/Kubernetes walkthroughs -- this is
opt-in and doesn't apply unless you've configured cluster mode.

| Option | Default | Meaning |
|---|---|---|
| `--burst` | off | Process whatever's queued right now, then exit, instead of listening indefinitely -- useful for testing/CI. |

```bash
export SECLOGX_BROKER_URL=redis://broker:6379/0
seclogx worker
```

Exits with an error immediately if `SECLOGX_BROKER_URL` isn't set --
there's nothing to consume without a broker configured.

## `seclogx cluster config`

Prints the distributed-mode configuration resolved from the environment
(`SECLOGX_STORAGE_BACKEND`/`SECLOGX_S3_*`/`SECLOGX_BROKER_URL`) as JSON.
Never prints credentials -- those are never read into this configuration
in the first place (see [10. Distributed deployment](10_distributed_deployment.md)).

```bash
seclogx cluster config
```

## `seclogx cluster status`

Reports live `seclogx worker` processes and queue depth for the
configured broker. With no `SECLOGX_BROKER_URL` set, says so and exits
cleanly -- ingest/hunt are running locally, not distributed, so there's
no cluster to report on.

```bash
seclogx cluster status
```

Next: [06. Python API](06_python_api.md) for the equivalent Python/notebook surface.
