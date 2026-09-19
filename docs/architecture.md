# Architecture

seclogx turns scattered forensic acquisitions -- `.evtx`, on-disk
Scheduled Task definitions, IIS/nginx/Apache/Tomcat access and error
logs, Exchange CSV logs, Linux syslog/auditd/systemd-journal exports,
MySQL/MariaDB/PostgreSQL/MSSQL/Oracle database logs, Tencent Cloud Host
Security client logs, and Windows Registry hives -- into one queryable,
huntable case workspace,
using set-based DuckDB SQL for canonical conversion. There are two
pipelines sharing one case workspace and one query layer: the EVTX
pipeline (stages 1-3 below) and a second one for everything else ("Non-EVTX
log families" further down). `Case.ingest()` walks every `--source` root
exactly once (`ingest/scan.py:scan_sources()`, bucketing files for both
pipelines from a single pass instead of two independent tree walks) and
then shares a total local `workers` budget across both pipelines. With
`workers=1`, the pipelines run serially in the calling process; with a
larger budget, they can parse concurrently. Each has a bounded worker
queue underneath, and an
optional progress callback (`ingest/jobs.py:ProgressReporter`) is threaded
through both, which is what backs `seclogx ingest`'s live progress display
and its `--background`/`ingest-status` job tracking (see
[08. Performance & scale](guides/08_performance_and_scale.md)).
`query.py`'s `CaseDB` and the plain-language `search.py` interface sit on
top of whichever tables either pipeline produced, with no distinction
between them at the query layer.

```
 .evtx files (multiple hosts/paths)
        |
        v
 [1] discovery + parallel staging  (ingest/evtx/discovery.py, ingest/evtx/stage.py, ingest/evtx/orchestrator.py)
        |  ProcessPoolExecutor, one worker per file
        v
 cases/<name>/staging/<batch_id>/<host>/*.ndjson.gz   (+ chunk manifests via IngestReport)
        |
        v
 [2] DuckDB bulk flatten  (ingest/evtx/flatten.py, schema.py)
        |  set-based SQL over bounded groups of staged shards
        v
 cases/<name>/lake/events/host=<h>/channel=<c>/*.parquet
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
directory). The shared scanner deduplicates physical file identity where
available, falling back to a resolved path; `ingest/common.py` holds the
`SourceSpec`/`sha256_file`/`parse_source_arg` primitives it shares with
the non-EVTX pipeline's own discovery module (see "Non-EVTX log
families" below).

`ingest/evtx/stage.py` runs in a worker process per file
(`ingest/evtx/orchestrator.py` coordinates via `ProcessPoolExecutor` --
files are independent and parsing is CPU/IO-bound, so this is where
parallelism buys speed). Each worker streams `PyEvtxParser.records_json()`
straight to `staging/<batch_id>/<host>/` with minimal Python-side
transformation. `ingest/staging.py:StagingWriter` rotates gzip NDJSON
shards at record boundaries, targeting 64 MiB of uncompressed encoded
bytes by default. It retains one encoded record, not a shard-sized
Python buffer; compression writes use a bounded 256 KiB buffer. Batch
directories isolate independent ingest attempts.
Staged NDJSON is gzipped (level 1): rendered-as-JSON EVTX
records run considerably larger than the source binary `.evtx` (verbose
field names, string-encoded binary values), and `staging/` is kept by
default (see "Case workspace layout" below) -- uncompressed, that
combination was the dominant driver of a case directory growing to
several times the source evidence size. DuckDB's `read_ndjson`
(Stage 2) decompresses `.gz` input transparently, so
nothing downstream treats compressed and uncompressed staging
differently.

With `keep_raw=True`, raw XML is indexed by event record ID in a temporary
SQLite database on disk, then looked up during the JSON pass. This avoids
a whole-file XML dictionary, while retaining the cost of an extra parse,
SQLite I/O, and temporary disk space. XML capture remains best effort.

Staging catches parse failures at the file level and records a `partial`
status with the exact number of records recovered, rather than letting a
partial read pass as a silent success -- `ingest/evtx/manifest.py`'s
`StagedFile`/`IngestReport` are the direct fix for the "ELK silently
drops records on import" pain point this tool exists to solve. See
`docs/known_limitations.md`'s "Ingestion / schema" section for exactly
when this triggers (a corrupted chunk partway through a file).
(`ingest/common.py` also holds the `StageStatus` vocabulary and `now_iso()`
helper both pipelines' manifests share.)

## Stage 2: DuckDB bulk flatten

On a staged path, after staging completes, its orchestrator groups shards
by their recorded uncompressed size (256 MiB per conversion by default).
`ingest/evtx/flatten.py` reads each group in a
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
transparently on read.

`IngestOptions`, exported by `seclogx`, supplies `memory_limit="2GB"`,
`threads=2`, `staging_chunk_bytes=64 * 1024 * 1024`, and
`flatten_batch_bytes=256 * 1024 * 1024`, and `staging_format="auto"`. Both `Case.ingest(options=...)`
and `Case.ingest_background(options=...)` accept it. Chunk and batch
sizes are byte targets: indivisible records/shards can exceed a target.
Encoded records above 32 MiB are explicitly rejected.

The process-local `CONVERSION_LOCK` serializes DuckDB ingest conversions
within one coordinator or Notebook process. It does not coordinate
separate processes/machines or limit unrelated queries. DuckDB's memory
setting applies to one conversion instance's managed memory, not total
RSS: parser processes, Python objects, library buffers and other jobs
need additional memory. Windows local storage still pre-creates Hive
partition directories. Auxiliary staging records a bounded partition set,
so it usually avoids a second scan; legacy manifests, unsupported values,
or exceeded metadata bounds retain the scan fallback. EVTX retains its
existing partition scan.

## Stage 3: query + detection

`query.py`'s `CaseDB` registers one view per table subdirectory found
under `lake/` (`read_parquet(..., hive_partitioning=true,
union_by_name=true)` each) -- `events` for Windows Event Log, plus
whichever of `web_logs`/`web_error_logs`/`scheduled_tasks`/
`exchange_message_tracking`/`exchange_logs`/`syslog`/`auditd_logs`/
`journal_logs`/`db_logs`/`qcloud_logs`/`registry` the case has data for -- and exposes
`.sql()`, a generic `.table(name)` (full contents of any table as a
DataFrame), and a handful of convenience filters, always returning
pandas DataFrames. `Case` mirrors this with a named, DataFrame-returning
accessor per log family (`web_logs()`, `web_error_logs()`,
`scheduled_tasks()`, `exchange_message_tracking()`, `exchange_logs()`,
`syslog()`, `auditd_logs()`, `journal_logs()`, `db_logs()`,
`qcloud_logs()`, `registry()`)
-- the same first-class treatment
`events` gets via `summary()`/`hosts()`/`channels()`, so no log family
requires raw SQL just to get a DataFrame. See `docs/schema.md` for every
table's full column list.

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
`Iterator[pd.DataFrame]` of roughly `chunksize`-row chunks. This bounds
result delivery by row count when the caller releases each chunk; row
width, retained chunks, and DuckDB joins/sorts/aggregations still consume
additional memory. `IngestOptions` configures ingest conversions, not
these query connections or pandas allocations. See "Bounded-memory access for
large tables" in
[03. Querying & search](guides/03_querying_and_search.md) for the full
mechanism and usage examples.

The table/query accessors have
`_chunks` siblings built the same way (`Case.query_chunks()`,
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
   check it looks like `{...}`) breaks silently whenever a JSON-object
   column is all-NULL in a given case; reading the declared type doesn't
   have that failure mode. JSON *array*
   columns (`scheduled_tasks.actions`/`triggers`) are excluded from this
   even though they're declared JSON too -- keyed extraction doesn't
   apply to a list the same way. An unresolvable field raises
   `UnknownFieldError` listing the table's actual columns, rather than a
   raw "column not found" from DuckDB -- but only on a table with no
   JSON-object catchall to fall back to (e.g. `scheduled_tasks`); on a
   table that has one (`events`, `web_logs`, ...) an unknown key is
   indistinguishable from "a real key just not present in this data,"
   and both correctly return zero matches instead (see
   `docs/known_limitations.md`'s "Plain-language search" section).
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
   skip the eager-result check and deliver one DataFrame at a time
   (the same `sql_chunks()`/`export_chunks_to_csv()` path described above).
   This does not impose a hard memory ceiling on query execution.

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

Hunting still materializes each rule's matches as a DataFrame, retains
them, and concatenates the results. There is no `hunt_chunks()` path or
search-style eager-result guard; distributed hunting also returns match
frames to the coordinator. A broad rule can therefore exceed available
memory even when ingest and ordinary chunked queries remain bounded.

`timeline.py` is a thin cross-host, filterable time-sorted view over the
same `events` table.

## Non-EVTX log families

The shared source scan also feeds a separate staging/flatten pipeline for
artifacts that aren't `.evtx` at all: on-disk Scheduled Task definitions,
IIS/nginx/Apache/Tomcat HTTP access **and** error/diagnostic logs, IIS
HTTP.sys (HTTPERR) logs, Exchange's self-describing CSV logs, three
Linux log families (generic syslog -- which is also where `auth.log`/
`secure` content lands, see below -- the Linux Audit Framework/auditd,
and systemd journal export), database server logs (MySQL/MariaDB
error/general/slow query logs, PostgreSQL, MSSQL, Oracle alert log),
Tencent Cloud Host Security client text logs (YDService, HIDS/YDLive,
vulnerability/baseline scanners, YDFlame/YDUtils/YDQuaraV2, YDEyes), and
Windows Registry hives (SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT/NTUSER/
UsrClass -- binary hive parsing delegated to the `regipy` dependency,
the same "trust a library for a complex binary forensic format" choice
already made for `.evtx` via the `evtx` dependency)
(`ingest/logsources/discovery.py`, `ingest/logsources/stage.py`,
`ingest/logsources/orchestrator.py` + `ingest/logsources/flatten.py` --
this second pair mirrors the EVTX pipeline's own orchestrator/flatten
split), orchestrated from `Case.ingest()`
alongside the EVTX pipeline; see `docs/known_limitations.md` for what
happens when a source has one but not the other.

The default auxiliary path (`direct_parquet=False`) is:

```
 same --source PATH[:HOST] inputs
        |
        v
 [1] classify   (ingest/logsources/sniff.py)
        |  content-sniffed, not trusted from filename/extension --
        |  forensic exports routinely rename/relocate files
        v
 scheduled_task | iis | web_access | web_error_{nginx,apache,tomcat} | iis_httperr
   | exchange_message_tracking | exchange_generic | syslog | auditd
   | journal_export | mysql_error | mysql_general | mysql_slow
   | postgresql | mssql | oracle_alert | qcloud_{ydservice,go,scanner,ydeyes}
   | registry_hive | unknown
        |
        v
 [2] parse + stage  (ingest/logsources/parsers/{scheduled_tasks,iis,webaccess,weberror,exchange,syslog,auditd,journal,dblogs,qcloud,registry}.py)
        |  dispatched by ingest/logsources/orchestrator.py's
        |  bounded worker queue, one file task per worker -- emits each
        |  completed dict to gzip NDJSON or bounded Arrow/ZSTD shards under
        |  staging_aux/<batch_id>/<host>/
        v
 [3] flatten    (ingest/logsources/flatten.py, ingest/logsources/schema.py)
        |  DuckDB reads bounded shard groups for each table off disk
        |  (read_ndjson or streaming Arrow reader, fixed text columns) and applies
        |  canonical TRY_CAST expressions, with missing fields as NULL
        v
 cases/<name>/lake/{web_logs,web_error_logs,scheduled_tasks,exchange_message_tracking,exchange_logs,syslog,auditd_logs,journal_logs,db_logs,qcloud_logs,registry}/host=<h>/[log_type=<t>/]*.parquet
```

**`syslog` covers `auth.log`/`secure` too -- there's no separate sniff
kind or table for it.** Both are the same BSD/RFC-3164-or-RFC-5424
envelope as `/var/log/syslog`; only the program names inside (`sshd`,
`sudo`, `su`, `useradd`, ...) distinguish auth-relevant content, and that
distinction is made afterward, on already-ingested data, by
`ingest/logsources/parsers/syslog.py`'s `extract_auth_events()` (exposed
as `Case.auth_events()` / `seclogx auth`) -- the same "derived heuristic
view over an already-ingested table" pattern `Case.suspicious_tasks()`
uses over `scheduled_tasks`, not a separate ingest-time table.

Access logs (`web_logs`) and error/diagnostic logs (`web_error_logs`) are
each web applications' two major log categories, and are kept as
separate tables since they're structurally unrelated (access logs have a
request/response shape; error logs are severity + free text).

After discovery's suffix/empty-file filters, auxiliary classification
uses content (see `sniff.classify_file`) because these artifacts are
routinely renamed or relocated during acquisition (a live Task Scheduler
task file has *no* extension at all). A classified file matching none of
the supported formats is reported as `unrecognized`
(`AuxIngestReport.unknown_samples`). This is not an inventory of filtered
or unreadable paths; see the discovery caveat in known limitations.

IIS and Exchange logs are both self-describing (`#Fields:` header naming
the columns actually enabled for that site/log), so the parsers read the
header rather than assuming a fixed field set. nginx/Apache/Tomcat access
logs are not self-describing this way (unlike their *error* logs, which
are engine-specific and unambiguous) -- see `docs/known_limitations.md`'s
"Non-EVTX log ingestion" section for exactly which formats get a real
detection versus a best-effort path/filename heuristic
(`sniff.guess_web_log_type`).

Text log and registry parsers expose an `emit` path used by ingest.
Their public collecting calls still return complete lists when `emit`
is omitted; those compatibility calls are not bounded by record count.
`textdecode.iter_text_lines` validates encoding through fixed-size reads
before emitting any rows, then reopens the file for strict decoding.
This adds sequential I/O but prevents a late decoding failure from
switching encoding after part of a file has already been emitted.
QCloud retains its BOM-required UTF-16 detection policy. Exchange CSV
keeps quoted multiline fields and their original line endings; multiline
parsers emit completed logical records.

Auxiliary flattening declares each input field as VARCHAR before canonical
casts, instead of sampling and inferring a schema for each shard group.
This prevents date-shaped free text from becoming a timestamp and changing
spelling when different shard boundaries produce different samples.

`staging_format="auto"` selects Arrow IPC/ZSTD level 1 for auxiliary source
files at least 16 MiB, and gzip NDJSON for smaller files. Explicit `arrow`
and `ndjson` override the selection. Arrow buffers are bounded by a 16 MiB
conservative estimate and 16,384 rows, with the same 32 MiB encoded-record
ceiling; one large record can exceed the batch target. IPC schemas fix raw
columns as strings, then DuckDB applies the existing canonical casts. The
reader opens one shard at a time. A fixed 1 MiB output buffer coalesces IPC
metadata and column writes; closing the sink must succeed before a shard
is published. Mixed formats for one table are converted
in separate groups. Auxiliary Parquet uses ZSTD level 1. EVTX staging is
unchanged. This default path writes intermediate files before conversion.

An optional `seclogx-native` companion package parses compatible UTF-8 CLF/
Combined and IIS access logs directly into bounded Arrow string buffers. Its
Rust loop releases the GIL; Arrow C Data capsules exchange batches inside the
file worker without recreating Python row dictionaries. Batch validation,
staging, bounded partition metadata and canonical SQL remain in the main
package. Only small manifests cross process boundaries.
`IngestOptions.parser_backend` defaults to `python`, keeping the compatibility
path. Explicit `auto` or strict `native` selects optional native parsing;
on the staged path, auto requires Arrow staging and falls back when the component or input is
unsupported. If a capability mismatch occurs after accepting batches, the
worker aborts and deletes all of that source's shards before a complete Python
replay. It does not retry source changes, I/O failures or malformed batches. Per-file reports
record the actual backend and fallback reason. Native parsing retains the
preparation/hash pass, and the staged path retains intermediate IPC storage.

`IngestOptions(parser_backend="auto", direct_parquet=True)` enables an alternative path in
`ingest/logsources/direct.py` for compatible UTF-8 Common/Combined and IIS
sources. It requires `keep_staging=False`, local execution/storage without a
broker, and `parser_backend="auto"` or `"native"`. Small files are eligible;
`staging_format` applies to other sources and compatibility replay, not this
direct path. The coordinator removes eligible sources from its ordinary queue,
finishes the remaining staging jobs and closes their pool, then converts direct
sources sequentially. The ordinary worker budget is unchanged. Each direct
conversion holds the same `CONVERSION_LOCK` as EVTX and staged flattening for
its DuckDB lifetime, sharing one configured conversion memory/thread budget
within that process; independent processes remain separate.

The native producer feeds bounded raw VARCHAR Arrow batches to DuckDB through
an in-process reader. Existing canonical SQL writes ZSTD Parquet privately
under `<case>/_ingest_private/`, outside the queryable `lake/` tree. After
conversion, reader/writer closure and source identity checks, the source's
completed output is published under its normal `web_logs` Hive partition.
Ordinary parse errors can publish an accepted prefix as `partial`; zero valid
rows produce a failed manifest without a Parquet file. I/O, source changes,
invalid batch contracts and conversion failures are fatal and remove that
source's private output. Earlier published sources are not rolled back.

In auto mode, unavailable/incompatible native components, encodings or syntax
fall back to whole-source Python staging after private output cleanup. The
same `PreparedText` identity/encoding is passed to staging, with native and
direct parsing disabled; a change cannot be hidden by preparing a new source.
Strict native mode fails instead. Hash and encoding preparation remain a
pre-read. Direct and later staged conversions share one batch timestamp.
Manifests distinguish parser selection (`parser_backend`, `backend_reason`)
from output (`output_format`, `parquet_paths`); direct results are counted once
and skipped by staged flattening and shard cleanup.

This source-level publication is not an atomic ingest transaction, a query
snapshot or an idempotent commit. A crash may leave `_ingest_private` files;
there is no automatic private-file recovery or resume protocol.

Text preparation computes SHA-256 and strict UTF-8 validation in one pass.
Fallback encodings retain their complete validation and priority order.
Parsing reuses the prepared encoding only inside a matching path/policy
scope. File identity, size and timestamps are checked for ordinary source
changes; this is not an immutable evidence snapshot. A detected change or
staging persistence error is fatal rather than published as a partial parse
when detected during parsing. A preparation read/change failure is reported
as a failed source before rows are emitted. Already-rejected UTF-8 is not
decoded again during fallback. These checks cover prepared text logs;
EVTX, Registry and task XML retain their separate hash/read paths.
Partition collection is bounded to 4,096 values/1 MiB per source, and uses
the canonical text spelling before Hive path escaping.

Physical text lines have an 8 Mi-character limit; logical-record limits
and exceptions are documented in [known limitations](known_limitations.md).
Registry traversal uses a seekable file-backed hive and emits rows;
transaction-log recovery still uses regipy's potentially in-memory path.
Scheduled Task XML remains a whole-document parser, with an 8 MiB
document limit enforced by ingest. Supported non-EVTX files are no longer
excluded simply because their source size exceeds 2 GiB.

## Case workspace layout

```
cases/<case_name>/
  case.json                     # hosts, source paths, ingest run history
  staging/<batch_id>/<host>/*.ndjson.gz      # one or more gzip shards per source EVTX
  staging_aux/<batch_id>/<host>/*.{ndjson.gz,arrow}  # bounded auxiliary shards
  _ingest_private/               # unpublished direct Parquet / DuckDB scratch
  logs/ingest_<batch_id>.log    # reconciliation summary per ingest run
  lake/
    events/host=<h>/channel=<c>/*.parquet
    web_logs/host=<h>/log_type=<t>/*.parquet
    web_error_logs/host=<h>/log_type=<t>/*.parquet
    scheduled_tasks/host=<h>/*.parquet
    exchange_message_tracking/host=<h>/*.parquet
    exchange_logs/host=<h>/log_type=<t>/*.parquet
    syslog/host=<h>/*.parquet
    auditd_logs/host=<h>/record_type=<r>/*.parquet
    journal_logs/host=<h>/*.parquet
    db_logs/host=<h>/log_type=<t>/*.parquet
    qcloud_logs/host=<h>/log_type=<t>/*.parquet
    registry/host=<h>/hive_type=<t>/*.parquet
```

`query.py`'s `CaseDB` creates a view per subdirectory of `lake/` that
actually contains Parquet files (named after the subdirectory), so a case
only ever exposes tables it has ingested data for, and a future log
family only needs a lake subdirectory to become queryable -- no changes
to `query.py` itself.

Only `lake/` is affected by cluster mode's storage backend (see below) --
`case.json`, `staging/`, `staging_aux/`, and `logs/` always stay on
whatever local/NFS directory `--case-root` points at, in every mode.

## Why not Dask / a distributed query engine -- and what got distributed instead

Designed for a single workstation by default, not a cluster: DuckDB gives
lazy, out-of-core *query execution* with predicate pushdown over Parquet
without any cluster setup, and parsing is parallelized locally via
`ProcessPoolExecutor`. The other half of "no cluster needed at real-world
scale" is bounded-memory *delivery* of results to the analyst (see
"Bounded-memory delivery" above) -- lazy execution underneath doesn't
help if the last step still materializes the whole result as one
DataFrame. **This is still exactly true for query execution**: DuckDB
remains the only query engine, and any single query or Sigma rule still
runs on exactly one process. No distributed SQL planner was added, and
none is planned -- that would mean reimplementing a distributed OLAP
engine, not extending this one.

What *did* get built, opt-in, is `src/seclogx/distributed/` (see
[10. Distributed deployment](guides/10_distributed_deployment.md) for the
user-facing guide): a `JobQueue` abstraction (`LocalJobQueue`, the same
`ProcessPoolExecutor` behavior as always; `RQJobQueue`, Redis-backed via
`rq`, consumed by `seclogx worker` processes) that both ingest
orchestrators and `detect/hunt.py`'s rule loop dispatch through instead of
constructing a process pool directly, plus a `StorageBackend` abstraction
(`LocalStorageBackend`; `S3StorageBackend`, via DuckDB's `httpfs`
extension for the Parquet I/O and boto3 for cheap metadata/listing) that
`CaseDB` and the flatten step of both pipelines use instead of raw
`pathlib` calls against `lake/`. This is exactly the previously-anticipated
extension point realized: **the partitioned Parquet lake is what makes
this possible without touching ingest stages 1-2's actual parsing logic
or query stage 3's actual DuckDB execution** -- "distributed" here means
job-level parallelism (many independent DuckDB processes/queries against
one shared lake), never intra-query execution. Activation is entirely
environment-variable driven (`SECLOGX_BROKER_URL`/`SECLOGX_STORAGE_BACKEND`
and friends) with zero new CLI flags on any existing command, and default
(no env vars set) behavior is unchanged from before this existed -- see
`distributed/config.py`'s `ClusterConfig`.

Two correctness gaps this surfaced (and fixed) along the way, independent
of whether cluster mode is ever turned on:

- `flatten_case`/`flatten_table`'s `COPY ... TO ... PARTITION_BY (...)`
  had no unique-filename guarantee across independent COPY invocations --
  fine when flattening was always serialized per case (true before this),
  but a collision risk when independent coordinators flatten
  into the same case concurrently. DuckDB's
  `FILENAME_PATTERN '{uuid}'` COPY option assigns distinct output names.
  This does not make a whole ingest atomic. The finite
  set of local Hive partition directories is also pre-created with
  `mkdir(exist_ok=True)` before COPY, avoiding a Windows race when two
  DuckDB connections create the same new partition simultaneously -- no
  lock is needed for this piece.
- `Case._load_meta`/`_save_meta`'s `case.json` read-modify-write had no
  lock at all -- a latent lost-update race even with two plain `seclogx
  ingest` runs on one machine, not just a cluster-mode concern. Now always
  lock-protected (`distributed/locking.py`): a stdlib-only file lock
  locally (no new dependency for default use), a Redis-based lock instead
  once a broker is configured (more reliable than a POSIX file lock over a
  network filesystem for coordinating genuinely separate machines).

**Default ingest still separates staging from conversion.** Text/registry
records are emitted to disk without retaining a whole file's rows, and only
shard manifests cross the worker boundary. Optional direct conversion bypasses
those shards for compatible web sources. Other formats and compatibility
replays still complete staging before bounded flatten calls, so temporary disk
usage can grow with their complete staged dataset. File discovery and manifests
scale with file/shard count. The local queue bounds in-flight tasks; there is
no general overlapped staging/flattening pipeline with disk-space backpressure.

`keep_staging=False` alone deletes completed staging rather than enabling direct
conversion. Resumable/idempotent ingest and atomic queryable snapshots are not
implemented. Resource targets do not guarantee a fixed
throughput or RSS for arbitrary formats, record sizes or machines.
Repeated ingestion can add duplicate rows, and a failure after some
flatten batches were written can leave partial output. Batch-isolated
scratch space and unique Parquet filenames do not provide a transaction
or a commit manifest for the lake. See the
[performance guide](guides/08_performance_and_scale.md) for resource settings
and their limits.
