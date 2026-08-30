# Architecture

seclogx turns scattered forensic acquisitions -- `.evtx`, on-disk
Scheduled Task definitions, IIS/nginx/Apache/Tomcat access and error
logs, Exchange CSV logs -- into one queryable, huntable case workspace,
favoring set-based DuckDB SQL over per-record Python wherever possible
(validated during design: the `evtx` package's real bottleneck is
per-record Python marshaling, not parsing). This is two parallel
pipelines sharing one case workspace and one query layer: the EVTX
pipeline (stages 1-3 below, the original and still the most
performance-critical path) and a second one for everything else ("Non-EVTX
log families" further down). `Case.ingest()` runs both over the same
`--source` inputs in one call; `query.py`'s `CaseDB` and the plain-language
`search.py` interface sit on top of whichever tables either pipeline
produced, with no distinction between them at the query layer.

```
 .evtx files (multiple hosts/paths)
        |
        v
 [1] discovery + parallel staging  (ingest/evtx/discovery.py, ingest/evtx/stage.py, ingest/evtx/orchestrator.py)
        |  ProcessPoolExecutor, one worker per file
        v
 cases/<name>/staging/<host>/*.ndjson   (+ staging/manifest via IngestReport)
        |
        v
 [2] DuckDB bulk flatten  (ingest/evtx/flatten.py, schema.py)
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

`ingest/evtx/discovery.py` recursively finds `.evtx` under one or more `--source
PATH[:HOST]` inputs (forensic acquisitions rarely live under one tidy
directory) and dedupes by resolved path; `ingest/common.py` holds the
`SourceSpec`/`sha256_file`/`parse_source_arg` primitives it shares with
the non-EVTX pipeline's own discovery module (see "Non-EVTX log
families" below).

`ingest/evtx/stage.py` runs in a worker process per file
(`ingest/evtx/orchestrator.py` coordinates via `ProcessPoolExecutor` --
files are independent and parsing is CPU/IO-bound, so this is where
parallelism buys speed). Each worker streams `PyEvtxParser.records_json()`
straight to `staging/<host>/<file>.ndjson` with minimal Python-side
transformation.

Corrupted chunks are a real, observed failure mode (see
`docs/known_limitations.md`): the parser raises at the generator level
rather than yielding a per-record error, so a bad chunk aborts the rest
of that file's parse. Staging catches this at the file level and records
a `partial` status with the exact number of records recovered --
`ingest/evtx/manifest.py`'s `StagedFile`/`IngestReport` never let a partial
read pass as a silent success, which is the direct fix for the "ELK
silently drops records on import" pain point this tool exists to solve.
(`ingest/common.py` also holds the `StageStatus` vocabulary and `now_iso()`
helper both pipelines' manifests share.)

## Stage 2: DuckDB bulk flatten

`ingest/evtx/flatten.py` reads all staged NDJSON for an ingest batch in one
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

### Bounded-memory delivery: `.sql()`/`.table()` vs. `.sql_chunks()`/`.table_chunks()`

DuckDB executes lazily with predicate pushdown over the Parquet lake, but
`.sql()`/`.table()` still call `.fetchdf()`, which materializes the
*entire* result as one pandas DataFrame -- fine for a filtered or
aggregated result, but any table here can realistically reach real-world
log volumes (web access/error logs especially, easily terabyte-scale
across a case), at which point one in-memory DataFrame for a whole table
is the actual bottleneck, independent of how lazy the query engine
underneath is. `.sql_chunks()`/`.table_chunks()` use DuckDB's
`fetch_df_chunk()` on a dedicated cursor instead, yielding an
`Iterator[pd.DataFrame]` of roughly `chunksize`-row chunks -- bounded
memory regardless of total result size. Verified empirically: reading 5M
rows via chunks added ~190MB of peak RSS against ~2.7GB for `fetchdf()`
on the same query (bounded vs. proportional-to-data-size).

Every DataFrame-returning accessor -- `CaseDB`'s and `Case`'s alike -- has
a `_chunks` sibling built the same way (`Case.query_chunks()`,
`Case.web_logs_chunks()`, `Case.timeline_chunks()`, ...), and the CLI
(`query`/`table`/`tasks`/`timeline`) uses the chunked path automatically
for both `--out` (streamed straight to CSV, one chunk at a time -- see
`cli/_render.py`'s `export_chunks_to_csv`) and the console preview
(`print_df_chunks` pulls only enough rows for the table, never the whole
result, at the cost of not being able to report an exact "N more rows"
count without materializing everything to know it).

### Querying without SQL: `search.py`

`seclogx search` / `Case.search()` let an analyst filter any table with
plain field/operator/value conditions -- no SQL. `search.py` translates
these into the same parameterized SQL `.sql()`/`.sql_chunks()` already
run, in three steps:

1. **Field resolution** (`resolve_field`): a field name that matches one
   of the table's real columns is used directly; otherwise it's looked up
   as a key inside whichever of the table's columns hold a JSON *object*
   (`event_data`, `extra`, `fields`, ...). Which columns those are comes
   from this project's own schema modules (`schema.py`'s `CORE_COLUMNS`,
   `ingest/logsources/schema.py`'s `TABLES`) -- their declared JSON-type
   annotations -- rather than DuckDB's catalog, because every JSON-bearing
   column here is physically stored as VARCHAR (see schema.py's
   `event_data` comment), so asking DuckDB "is this column's type JSON"
   always says no. Content-sniffing the catalog instead (sample a value,
   check it looks like `{...}`) was the first approach tried and it broke
   silently whenever a JSON-object column was all-NULL in a given case;
   reading the declared type doesn't have that failure mode. JSON *array*
   columns (`scheduled_tasks.actions`/`triggers`) are excluded from this
   even though they're declared JSON too -- keyed extraction doesn't
   apply to a list the same way. An unresolvable field raises
   `UnknownFieldError` listing the table's actual columns, rather than a
   raw "column not found" from DuckDB.
2. **Operator compilation** (`_condition_sql`): `equals` casts both sides
   to VARCHAR and compares (optionally via `LOWER()` for the default
   case-insensitive behavior) -- deliberately always a text comparison so
   an analyst doesn't need to know or care whether the underlying column
   is numeric; `contains` is `LIKE`/`ILIKE` with the literal value's `%`/
   `_`/`\` escaped (it's a literal substring search, not a wildcard
   pattern); `regex` is `regexp_matches(expr, pattern, options)`, with
   `options='i'` for case-insensitive (DuckDB's regex case-insensitivity
   flag). Multiple values on one condition combine with OR (`status`
   equals 404 or 500); multiple conditions combine with AND by default,
   OR if `match="any"`.
3. **Memory-safety check** (reusing `CaseDB.estimate()`): `search()`
   estimates the result size before fetching and raises
   `ResultTooLargeError` -- naming `search_chunks()`/`search_to_csv()` as
   the alternatives -- rather than materializing a result too large for
   the machine's available memory. `search_chunks()`/`search_to_csv()`
   skip the check entirely, since they're memory-safe at any result size
   regardless (same `sql_chunks()`/`export_chunks_to_csv()` as the rest of
   the bounded-memory delivery story above).

`discover_fields()` (`seclogx fields` / `Case.fields()`) answers "what
can I even search on" by reading real data rather than documentation: it
fetches one bounded sample (`LIMIT sample_size`, default 5000 -- a single
query, safe at any table size) as a DataFrame, then for each column
either reports it directly (a real column) or, for whichever columns
`_json_object_columns` says hold a JSON object, `json.loads()`s every
sampled value in Python and aggregates the union of keys with a
popularity count and one example value per key. This is deliberately
plain Python over the sample rather than a SQL-side aggregation (e.g.
`json_keys()` + `unnest()`) -- simpler to get right, and the sample is
already bounded so there's no performance case for pushing it into SQL.

`query.py`'s `ResultSizeEstimate`/`CaseDB.estimate()` and
`memcheck.available_memory_bytes()` (best-effort, no new dependency:
`/proc/meminfo` on Linux, `os.sysconf` as a coarser POSIX fallback,
`GlobalMemoryStatusEx` via `ctypes` on Windows, `None` -- treated as
"unknown, be conservative" -- if none of those work) aren't
search-specific; anything wanting a "is this safe to fetch eagerly"
answer can reuse them the same way.

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
(`ingest/logsources/discovery.py`, `ingest/logsources/stage.py`,
`ingest/logsources/orchestrator.py` + `ingest/logsources/flatten.py` --
this second pair mirrors the EVTX pipeline's own orchestrator/flatten
split, unlike in earlier versions of this project where both lived in
one `logsources/ingest.py` file), orchestrated from `Case.ingest()`
alongside the EVTX pipeline; see `docs/known_limitations.md` for what
happens when a source has one but not the other.

```
 same --source PATH[:HOST] inputs
        |
        v
 [1] classify   (ingest/logsources/sniff.py)
        |  content-sniffed, not trusted from filename/extension --
        |  forensic exports routinely rename/relocate files
        v
 scheduled_task | iis | web_access | web_error_{nginx,apache,tomcat} | iis_httperr
   | exchange_message_tracking | exchange_generic | unknown
        |
        v
 [2] parse      (ingest/logsources/parsers/{scheduled_tasks,iis,webaccess,weberror,exchange}.py)
        |  dispatched by ingest/logsources/orchestrator.py's
        |  ProcessPoolExecutor, one worker per file -- straight to Python
        |  dicts (these formats are already line/element-oriented text,
        |  unlike EVTX, so no NDJSON staging step is needed)
        v
 [3] flatten    (ingest/logsources/flatten.py, ingest/logsources/schema.py)
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

Designed for a single workstation, not a cluster. DuckDB gives lazy,
out-of-core *query execution* with predicate pushdown over Parquet
without any cluster setup, and parsing is parallelized locally via
`ProcessPoolExecutor`. The other half of "no cluster needed at real-world
scale" is bounded-memory *delivery* of results to the analyst (see
"Bounded-memory delivery" above) -- lazy execution underneath doesn't
help if the last step still materializes the whole result as one
DataFrame. If a genuinely distributed use case shows up later, the
partitioned Parquet lake (stage 2's output contract) is the extension
point -- a distributed query engine could read the same lake without
changing stages 1-2.

**Ingest is not yet bounded-memory the same way query is.** The EVTX
pipeline is fine at real-world scale (stage 1 streams to NDJSON on disk
per file; stage 2's flatten reads that back via DuckDB's own streaming
`read_ndjson()`, never loading every record into a Python list at once).
The non-EVTX pipeline (`ingest/logsources/orchestrator.py`) does not have this
property yet: each worker parses a file straight to a Python
`list[dict]`, and `run_aux_ingest()` accumulates every file's rows for a
given table in memory (`by_table[table].extend(rows)`) across the whole
ingest batch before writing Parquet, rather than streaming to disk
per-file the way EVTX staging does. This is fine at the volumes exercised
so far (a batch of moderately-sized log files); an ingest batch
processing enough web/error/Exchange log files to reach real-world
terabyte-scale *in one run* would need the same stage-to-disk-then-bulk-
flatten treatment stage 2 already gives EVTX. Not yet implemented --
flagged here as the known boundary of "bounded memory," which currently
covers query/delivery (`.sql_chunks()`/`.table_chunks()`) but not this
specific ingest path.
