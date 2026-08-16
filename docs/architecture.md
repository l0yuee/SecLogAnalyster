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

`query.py`'s `CaseDB` registers a `events` view over the whole lake
(`read_parquet(..., hive_partitioning=true, union_by_name=true)`) and
exposes `.sql()` plus a handful of convenience filters, always returning
pandas DataFrames.

`detect/` compiles Sigma rules to DuckDB SQL via a custom pySigma backend
(`detect/backend.py`) and a field-mapping pipeline (`detect/pipeline.py`)
-- see `docs/sigma_backend.md` for how that works and how to extend it.
`detect/hunt.py` runs each rule, attaches ATT&CK tags (`attack.py`), and
reports rules that failed to convert or execute rather than dropping them
silently.

`timeline.py` is a thin cross-host, filterable time-sorted view over the
same `events` table.

## Case workspace layout

```
cases/<case_name>/
  case.json                     # hosts, source paths, ingest run history
  staging/<host>/*.ndjson       # raw records_json() output, one file per source .evtx
  logs/ingest_<batch_id>.log    # reconciliation summary per ingest run
  lake/host=<h>/channel=<c>/*.parquet
```

## Why not Dask / a distributed engine

Designed for realistic single-case volumes (<100GB) on one workstation.
DuckDB already gives lazy, out-of-core execution with predicate pushdown
over Parquet without any cluster setup, and the parsing stage is
parallelized locally via `ProcessPoolExecutor`. If a genuinely
distributed use case shows up later, stage 2's output contract (a
partitioned Parquet lake with a fixed schema) is the extension point --
a distributed query engine could read the same lake without changing
stages 1-2.
