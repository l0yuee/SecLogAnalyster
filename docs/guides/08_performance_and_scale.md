# 8. Performance and scale notes

**Language: English | [中文](08_performance_and_scale.zh-CN.md)**

**[Guide index](../index.md)** · [Python API](06_python_api.md) · [Distributed deployment](10_distributed_deployment.md)

Ingest streams text-log and registry records to disk and bounds each DuckDB
conversion's input. Resource use still depends on the formats, individual
record sizes, worker count and storage. This guide explains the available
controls and their limits; it does not promise a fixed throughput or total
process-memory ceiling.

## Explicit Notebook settings

Use the dedicated project environment for local Python and tests:

```bash
conda activate python314
python -m jupyterlab
```

Select the `python314` kernel and check `sys.executable` inside the Notebook;
starting the server in this environment does not change an existing kernel.

```python
from seclogx import Case, IngestOptions

c = Case.create("large_case")  # Case.open("large_case") in later sessions
options = IngestOptions(
    memory_limit="2GB",
    threads=2,
    staging_chunk_bytes=64 * 1024 * 1024,
    flatten_batch_bytes=256 * 1024 * 1024,
    staging_format="auto",
)
report = c.ingest([r"E:\evidence:HOST01"], workers=2, options=options)
print(report.summary_text())
```

The `IngestOptions` values above are the library defaults; `workers=2` explicitly reduces parsing parallelism. **2GB limits one DuckDB conversion instance's managed memory, not Notebook RSS or the whole process tree.** Python/native-library allocations, parsing workers, registry recovery, other queries and background jobs need additional memory. `threads` controls conversion threads separately from parsing workers.

`staging_format` controls supported auxiliary sources independently for each source file:

| Setting | Auxiliary staging |
|---|---|
| `"auto"` (default) | Arrow IPC / ZSTD level 1 for sources at least 16 MiB; gzip NDJSON below 16 MiB |
| `"arrow"` | Arrow IPC / ZSTD level 1 regardless of source size |
| `"ndjson"` | gzip NDJSON, compression level 1 |

EVTX staging remains NDJSON for all three settings. Auxiliary Parquet output uses ZSTD level 1 under either staging path. The CLI exposes the same selection as `--staging-format auto`, `--staging-format arrow` or `--staging-format ndjson`, including with `--background`.

## Optional native parsers

The separately installed [native component](../../native/README.md) implements
bounded Rust parsers for UTF-8 Common/Combined web access and IIS W3C access logs.
Install it in the same environment as the Notebook kernel and any ingest
workers. Existing `Case` methods and result schemas remain the same.

| `IngestOptions.parser_backend` | Behavior for recognized auxiliary sources |
|---|---|
| `"python"` (default) | Keep the Python compatibility path regardless of whether the component is installed |
| `"auto"` | Explicitly enable native parsing when the component, encoding, format and selected output path are compatible; otherwise use Python |
| `"native"` | Require native support; fail if unavailable or incompatible |

The CLI option is `--parser-backend auto|python|native`, including for background
ingest; the default is `python`. EVTX keeps its existing parser. When native parsing
is explicitly enabled on the staged path, with `staging_format="auto"`, small files
still select NDJSON and use Python; choose `staging_format="arrow"` to use native
parsing for them. Strict native mode is intended for compatible inputs, not a
mixed collection containing other recognized log families.

The native parser builds Arrow string buffers directly and releases the GIL
while reading and parsing. On the staged path, batches are consumed inside the same file worker;
the coordinator receives only a manifest. This avoids per-record Python dicts
on the native path. Canonical conversions still use the same DuckDB SQL.
Hashing and complete encoding validation still precede parsing. The default
path writes Arrow IPC staging before conversion; native parsing alone does not
remove that I/O or split a single source across workers.

If native parsing encounters an unsupported compatible syntax in `auto` mode,
ingest discards that file's native shards and replays the entire source through
Python. Such a fallback can require an extra read. Read/write errors and detected
source changes, and malformed native batches remain fatal. Ordinary parse errors retain the existing accepted
prefix behavior. Each `report.aux.staged_files` entry exposes `parser_backend`
and `backend_reason`, so availability is distinguishable from actual use.

## Optional direct Parquet conversion

`direct_parquet=False` is the default. For local compatible web access/IIS
sources, explicitly enable direct conversion and disable retained staging:

```python
from seclogx import Case, IngestOptions

web_case = Case.create("web_direct")
report = web_case.ingest(
    [r"E:\evidence\web:HOST01"],
    keep_staging=False,
    options=IngestOptions(parser_backend="auto", direct_parquet=True),
)
```

The CLI equivalent is `--parser-backend auto --direct-parquet --no-keep-staging`. Foreground and
background ingest accept these settings. Direct conversion requires local
storage, no configured broker, and `parser_backend="auto"` or `"native"`.
It consumes bounded native Arrow batches directly in DuckDB, using the same
fixed VARCHAR inputs, canonical SQL and ZSTD Parquet output. Small sources can
use it too: `staging_format` controls only compatibility replay and other
sources, and need not be `"arrow"` for direct conversion.

Ordinary auxiliary sources finish their worker-pool staging first. The pool
then closes, and eligible direct sources run one at a time in the coordinator.
This preserves the ordinary worker budget; it does not parallelize direct
sources. Each direct conversion shares `CONVERSION_LOCK` with EVTX and staged
flattening, so only one ingest DuckDB conversion uses its configured memory
and thread budget at a time within that process. The budget is still not an
RSS cap, and independent processes do not share the lock.

Hashing and strict encoding preparation remain a separate pre-read. In `auto`
mode, missing/incompatible components, encodings or syntax cause a complete
Python staging replay after private native output is removed. Replay reuses
the same prepared source identity and encoding. Strict `native` mode fails
instead. Source changes, I/O, malformed batches and conversion failures are
fatal; ordinary parse errors can publish the accepted prefix as `partial`.

Each source is written privately under `<case>/_ingest_private/`, outside
`lake/`, then published only after conversion, closure and source checks.
Zero recovered rows are reported as `failed` without publication. This is a
source-level boundary, not an atomic whole-ingest transaction: earlier
published files can remain after a later failure. A crash can leave private
files; automatic recovery, resume and duplicate prevention are not provided.
Manifest `parser_backend` / `backend_reason` describe parsing separately from
`output_format` (`staged` or `parquet`) / `parquet_paths`.

Publication uses a rename that refuses to overwrite an existing file on
Windows. On POSIX, the private output and destination must be on the same
filesystem and support hard links. If that publication step is unsupported or
fails, ingest reports an error; it does not switch to copying or Python replay.
These platform-specific rules do not mean every platform and dependency
combination has been validated.

## Worker budgets and background ingest

`workers` is the **total local parsing budget** across EVTX and auxiliary pipelines, including explicit values. Mixed inputs split it; `workers=1` runs both pipelines serially in the calling process. The default is at most eight workers, and the local queue bounds pending tasks. Distributed workers are managed separately; this does not set a cluster-wide memory ceiling.

`CONVERSION_LOCK` serializes ingest conversions within one coordinator or Notebook process. Parsing may continue concurrently. Separate processes, background jobs and notebooks do not share the lock.

For detached execution, use this **instead of** the foreground import:

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"], workers=2, options=options)
c.job_status(job_id)
```

The child uses the kernel's `sys.executable` and receives these ingest options.
Detaching frees the Notebook for other cells; it does not reduce the ingest's
work, memory or disk needs. Check for phase `done` or `failed` and inspect
`<case>/jobs/<job_id>.log` on failure. After `done`, reopen the case to query
with fresh views; an existing query connection is not refreshed by another
process. A background job is not a resumable transaction.

Do not run both examples against the same evidence to switch modes: repeated ingest can duplicate records. See [Python API](06_python_api.md) for callbacks and script guards.

## Memory and disk boundaries

- Text-log and registry parsers emit completed records during ingest. Direct parser calls without `emit` retain the full-list API and its memory cost. Scheduled Task XML remains a whole-document parse, limited to 8 MiB by ingest. Registry uses a file-backed hive; transaction-log recovery through regipy and exceptionally large individual values remain memory exceptions.
- During auxiliary text ingest, SHA-256 and strict UTF-8 validation share one bounded full-file pass, followed by the parsing pass. Non-UTF-8 sources retain the strict UTF-16/GB18030/Latin-1 fallback sequence and may require more reads; QCloud requires a UTF-16 BOM. Validation completes before any record is emitted. File identity, size and timestamps are checked when reusing this preparation; this is not an immutable evidence snapshot. Direct parser calls outside ingest still validate their input independently.
- Physical text lines have an 8 Mi-character limit. Logical-record and format limits also apply, including QCloud's 4 Mi characters/100,000 lines, database limits and CSV field size. Oversized records produce explicit errors; see [known limitations](../known_limitations.md).
- `staging_chunk_bytes` targets **uncompressed bytes**: encoded NDJSON bytes for gzip, or Arrow batch buffer bytes for IPC. Gzip shards rotate between records with a bounded 256 KiB write buffer. Arrow uses record batches bounded by 16,384 rows and a 16 MiB size estimate, rotating shards between batches, plus a 1 MiB output buffer per active writer. One record can exceed a batch/shard target; encoded records above 32 MiB are rejected.
- Scratch paths include batch IDs: `staging/<batch_id>/<host>/` and `staging_aux/<batch_id>/<host>/`. Sources on the staged paths complete staging before flattening bounded shard groups. `flatten_batch_bytes` is a target, and an indivisible shard can exceed it. File/shard metadata grows with its count, and the full staged dataset can accumulate before conversion, including other formats and compatibility replays when direct conversion is enabled.
- Both gzip and Arrow staging are **kept by default**. `keep_staging=False` alone removes that run's shards after successful conversion; it does not bypass staging or eliminate peak staging disk usage. Only explicitly enabled direct conversion skips these shards for compatible sources. Budget for source evidence, staging, Parquet and temporary working files together. Compression ratios depend on the source content.
- EVTX `keep_raw=True` uses temporary SQLite indexing instead of a whole-file XML dictionary. It still adds an XML parse, index I/O, larger output and temporary disk space; no fixed speed or memory multiplier is promised.
- The 2 GiB non-EVTX source-file exclusion has been removed. Supported large files reach their parser; record/document limits remain. A shared scan classifies both pipelines using bounded content peeks. Unknown files are reported without full hashing or parsing tasks.

DuckDB reads each bounded group into partitioned Parquet. Arrow staging feeds batches directly to DuckDB and avoids NDJSON serialization and reparsing between parsing and conversion. It still incurs Arrow construction/compression, reading, normalization and Parquet output costs.

Auxiliary staging also collects a bounded partition list, allowing Windows local storage to pre-create Hive directories without rereading all staged rows. Collection is limited to 4,096 partitions and 1 MiB of encoded partition values per source; a conversion group also falls back above 4,096 unique partitions. Legacy manifests, unsupported values or an exceeded bound retain the authoritative DuckDB `SELECT DISTINCT` scan. These limits disable the optimization, not the import. EVTX keeps its existing partition-discovery path; POSIX/object storage do not need the Windows directory pre-creation step.

Auxiliary conversion uses fixed VARCHAR input columns followed by canonical casts, without schema-inference sampling. Date-shaped free text therefore keeps its original spelling across different shard boundaries. Tomcat records exceeding 200 continuation lines are rejected before emitting the current entry; completed earlier records can remain in a partial file.

## Measure before increasing parallelism

Use a fresh case when comparing configurations on representative evidence.
Keep the input and measurement boundaries consistent, and check recovered
records as well as speed. Measure:

- Total elapsed time/throughput and scan, staging and flatten durations.
- Peak RSS of the coordinator **and all workers**, plus system free memory.
- Peak staging/temporary disk usage and final Parquet size.
- Discovered/successful/partial/failed files and recovered/written records.

Start with `workers=1` for a tighter budget and change one setting at a time. More workers can increase disk contention and memory even with streaming. Lower DuckDB memory can increase spilling or fail conversion; reserve temporary disk space and inspect reported errors.

Automatic resume, cross-run idempotency, atomic query snapshots and immediate flattening with disk-space backpressure are not implemented. Failure after some conversion groups were written can leave partial lake output. Retained shards help investigation but do not provide a resume/commit protocol.

After ingest, use filtered queries or `_chunks` accessors for large results. Unfiltered `.query()`/`.web_logs()` still materialize complete DataFrames; ingest options do not change query delivery. See [Querying & search](03_querying_and_search.md).

Next: [09. FAQ & limitations](09_faq_and_limitations.md).
