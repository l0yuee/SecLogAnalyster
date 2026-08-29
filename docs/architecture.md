# Architecture

seclogx turns scattered `.evtx` acquisitions into a queryable, huntable
case workspace in three stages, favoring set-based DuckDB SQL over
per-record Python wherever possible (validated during design: the `evtx`
package's real bottleneck is per-record Python marshaling, not parsing).

```
 .evtx files (multiple hosts/paths)
        |
        v
 [1] discovery + parallel staging  (discovery.py, ingest/stage.py, ingest/orchestrator.py)
        |  ProcessPoolExecutor, one worker per file
        v
 cases/<name>/staging/<host>/*.ndjson   (+ staging/manifest via IngestReport)
        |
        v
 [2] DuckDB bulk flatten  (ingest/flatten.py, schema.py)
        |  one set-based SQL statement over all staged files
        v
 cases/<name>/lake/host=<h>/channel=<c>/*.parquet
        |
        v
 [3] query + detection  (query.py, detect/*, timeline.py)
        |  DuckDB view + pandas, Sigma rules compiled to DuckDB SQL
        v
 pandas DataFrames (CLI tables/CSV, or directly in a notebook via Case)
```

## Stage 1: discovery + parallel staging

`discovery.py` recursively finds `.evtx` under one or more `--source
PATH[:HOST]` inputs (forensic acquisitions rarely live under one tidy
directory) and dedupes by resolved path.

`ingest/stage.py` runs in a worker process per file (`ingest/orchestrator.py`
coordinates via `ProcessPoolExecutor` -- files are independent and
parsing is CPU/IO-bound, so this is where parallelism buys speed). Each
worker streams `PyEvtxParser.records_json()` straight to
`staging/<host>/<file>.ndjson` with minimal Python-side transformation.

Corrupted chunks are a real, observed failure mode (see
`docs/known_limitations.md`): the parser raises at the generator level
rather than yielding a per-record error, so a bad chunk aborts the rest
of that file's parse. Staging catches this at the file level and records
a `partial` status with the exact number of records recovered --
`ingest/manifest.py`'s `StagedFile`/`IngestReport` never let a partial
read pass as a silent success, which is the direct fix for the "ELK
silently drops records on import" pain point this tool exists to solve.

## Stage 2: DuckDB bulk flatten

`ingest/flatten.py` reads all staged NDJSON for an ingest batch in one
DuckDB `read_ndjson(..., filename=true)` call, joins it against an
in-memory manifest table for provenance (host, source path, file hash),
and extracts every normalized column via the SQL expressions defined
once in `schema.py` (`EXTRACTION_SQL`) -- the single source of truth for
both the column list and how each column is derived. Missing JSON paths
extract to `NULL` rather than erroring, which is what absorbs the huge
per-provider field variance across hundreds of Windows event providers.

The result is written as Parquet, Hive-partitioned by `host` then
`channel` (`COPY ... PARTITION_BY (host, channel)`). DuckDB percent-encodes
partition values containing `/` (common in channel names like
`Microsoft-Windows-Sysmon/Operational`) and decodes them back
transparently on read -- verified empirically.

## Stage 3: query + detection

`query.py`'s `CaseDB` registers one view per table subdirectory found
under `lake/` (`read_parquet(..., hive_partitioning=true,
union_by_name=true)` each) -- `events` for Windows Event Log, plus
whichever of `web_logs`/`web_error_logs`/`scheduled_tasks`/
`exchange_message_tracking`/`exchange_logs` the case has data for -- and
exposes `.sql()`, a generic `.table(name)` (full contents of any table as
a DataFrame), and a handful of convenience filters, always returning
pandas DataFrames. `Case` mirrors this with a named, DataFrame-returning
accessor per log family (`web_logs()`, `web_error_logs()`,
`scheduled_tasks()`, `exchange_message_tracking()`, `exchange_logs()`) --
the same first-class treatment `events` gets via `summary()`/`hosts()`/
`channels()`, so no log family requires raw SQL just to get a DataFrame.

`detect/` compiles Sigma rules to DuckDB SQL via a custom pySigma backend
(`detect/backend.py`) and a field-mapping pipeline (`detect/pipeline.py`)
-- see `docs/sigma_backend.md` for how that works and how to extend it.
Most Sigma logsource categories target `events`; `category: webserver`
rules target `web_logs` instead (`LOGSOURCE_TABLE` in `pipeline.py`).
`detect/hunt.py` runs each rule against the right table, attaches ATT&CK
tags (`attack.py`), and reports rules that failed to convert or execute
(including "this case has no `<table>` table ingested") rather than
dropping them silently.

`timeline.py` is a thin cross-host, filterable time-sorted view over the
same `events` table.

## Non-EVTX log families

Every `--source` also gets a second discovery/staging/flatten pass, for
artifacts that aren't `.evtx` at all: on-disk Scheduled Task definitions,
IIS/nginx/Apache/Tomcat HTTP access **and** error/diagnostic logs, IIS
HTTP.sys (HTTPERR) logs, and Exchange's self-describing CSV logs
(`logsources/discovery.py`, `logsources/stage.py`, `logsources/ingest.py`,
orchestrated from `Case.ingest()` alongside the EVTX pipeline; see
`docs/known_limitations.md` for what happens when a source has one but
not the other).

```
 same --source PATH[:HOST] inputs
        |
        v
 [1] classify   (logsources/sniff.py)
        |  content-sniffed, not trusted from filename/extension --
        |  forensic exports routinely rename/relocate files
        v
 scheduled_task | iis | web_access | web_error_{nginx,apache,tomcat} | iis_httperr
   | exchange_message_tracking | exchange_generic | unknown
        |
        v
 [2] parse      (logsources/{scheduled_tasks,iis,webaccess,weberror,exchange}.py)
        |  ProcessPoolExecutor, one worker per file -- straight to Python
        |  dicts (these formats are already line/element-oriented text,
        |  unlike EVTX, so no NDJSON staging step is needed)
        v
 [3] flatten    (logsources/ingest.py, logsources/schema.py)
        |  explicit TRY_CAST per column per table -- same union_by_name
        |  stable-typing discipline as schema.py's event_data fix
        v
 cases/<name>/lake/{web_logs,web_error_logs,scheduled_tasks,exchange_message_tracking,exchange_logs}/host=<h>/[log_type=<t>/]*.parquet
```

Access logs (`web_logs`) and error/diagnostic logs (`web_error_logs`) are
each web applications' two major log categories, and are kept as
separate tables since they're structurally unrelated (access logs have a
request/response shape; error logs are severity + free text). Unlike
access-log format, nginx/Apache/Tomcat error-log format *is*
engine-specific and unambiguous, so classification for those is a real
detection, not the path/filename heuristic access logs need.

Unlike EVTX, classification never trusts a file's name or extension --
only content (see `sniff.classify_file`) -- because these artifacts are
routinely renamed or relocated during acquisition (a live Task Scheduler
task file has *no* extension at all). A file matching none of the
supported formats is reported as `unrecognized`, never silently dropped
(`AuxIngestReport.unknown_samples`).

IIS and Exchange logs are both self-describing (`#Fields:` header naming
the columns actually enabled for that site/log), so the parsers read the
header rather than assuming a fixed field set. nginx/Apache/Tomcat
Combined/Common Log Format is not self-describing and is
byte-identical across all three servers, so the specific server label is
a path/filename heuristic (`sniff.guess_web_log_type`), not a detection.

## Case workspace layout

```
cases/<case_name>/
  case.json                     # hosts, source paths, ingest run history
  staging/<host>/*.ndjson       # raw records_json() output, one file per source .evtx
  logs/ingest_<batch_id>.log    # reconciliation summary per ingest run
  lake/
    events/host=<h>/channel=<c>/*.parquet
    web_logs/host=<h>/log_type=<t>/*.parquet
    web_error_logs/host=<h>/log_type=<t>/*.parquet
    scheduled_tasks/host=<h>/*.parquet
    exchange_message_tracking/host=<h>/*.parquet
    exchange_logs/host=<h>/log_type=<t>/*.parquet
```

`query.py`'s `CaseDB` creates a view per subdirectory of `lake/` that
actually contains Parquet files (named after the subdirectory), so a case
only ever exposes tables it has ingested data for, and a future log
family only needs a lake subdirectory to become queryable -- no changes
to `query.py` itself.

## Why not Dask / a distributed engine

Designed for realistic single-case volumes (<100GB) on one workstation.
DuckDB already gives lazy, out-of-core execution with predicate pushdown
over Parquet without any cluster setup, and the parsing stage is
parallelized locally via `ProcessPoolExecutor`. If a genuinely
distributed use case shows up later, stage 2's output contract (a
partitioned Parquet lake with a fixed schema) is the extension point --
a distributed query engine could read the same lake without changing
stages 1-2.
