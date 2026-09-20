# 8. Performance and scale notes

**Language: English | [中文](08_performance_and_scale.zh-CN.md)**

**[Guide index](../index.md)** · [Python API](06_python_api.md) · [Distributed deployment](10_distributed_deployment.md)

Ingest streams text-log and registry records to disk and bounds each DuckDB
conversion's input. Resource use still depends on the formats, individual
record sizes, worker count and storage. This guide explains the available
controls and their limits; it does not promise a fixed throughput or total
process-memory ceiling.

## Automatic ingest in a Notebook

Complete the [one-time installation](01_getting_started.md#install), select the
`python314` Jupyter kernel and use the ordinary API:

```python
from seclogx import Case

c = Case.create("large_case")
report = c.ingest([r"E:\evidence:HOST01"])
print(report.summary_text())
```

Normal installation includes the Rust parser. Compatible local UTF-8
Common/Combined and IIS W3C sources automatically use native parsing, bounded
Arrow batches and direct Parquet output. Other sources use the compatibility
path. Analysts do not need to select an accelerator or tune a list of options.
Source hashing, strict encoding checks and canonical result schemas are retained.

Staging is **removed after successful conversion by default**, without deleting
source evidence. To retain intermediate files for diagnosis, explicitly pass
`keep_staging=True`; automatic selection then uses staging. This changes the
earlier default that retained staging.

## Automatic native parsing

The [native component](../../native/README.md) is built and installed with the
main package. It reads, parses and builds Arrow string buffers while releasing
the GIL. No per-record Python dictionaries cross the native boundary. Batches
stay inside a file worker or the direct-conversion coordinator; only manifests
cross process boundaries. The same DuckDB SQL normalizes the final rows.

The default `parser_backend="auto"` selects compatible native parsing and uses
Python for unsupported formats, encodings or syntax. If the installed extension
cannot load, runtime compatibility handling records the reason and uses Python;
this is distinct from a failed source installation, which requires build tools.
EVTX retains its Rust dependency, with one native thread per file worker. A late capability mismatch discards all private
native output for that source before replaying the entire source in Python.
Such replay can add a read. I/O errors, detected source changes and invalid
native batches are errors, not reasons to silently replay.

`report.aux.staged_files` and `report.aux.to_dataframe()` expose
`parser_backend` / `backend_reason` for each auxiliary source. Ordinary parse
errors preserve complete accepted prefixes as partial results.

## Automatic direct Parquet conversion

`direct_parquet=None` means automatic selection. With the ordinary defaults,
eligible Web/IIS files bypass IPC/NDJSON staging and feed bounded native Arrow
batches directly to DuckDB. This applies to local execution and local storage
without a broker. Small compatible sources are eligible too. Retained staging,
remote execution, object storage or explicit Python-only parsing selects the
staged path automatically. Foreground, background and CLI imports share these
defaults; no `--direct-parquet` switch is needed for normal local use.

Other auxiliary sources finish their worker-pool staging first. The pool then
closes, and direct sources run sequentially in the coordinator. Direct
conversion shares `CONVERSION_LOCK` with EVTX and staged flattening, keeping
one ingest DuckDB conversion memory/thread budget active at a time inside the
process. Independent processes do not share that lock.

Hashing and strict encoding preparation still precede parsing. Incompatible
native input reuses the same prepared source identity and encoding for complete
Python staging replay. Direct batches use the fixed VARCHAR input schema,
canonical SQL and ZSTD Parquet output; `staging_format` applies only to other
sources and compatibility replay.

Each direct source writes inside the attempt's `.ingest/<id>/` workspace.
After conversion, closure and source checks, it enters that attempt's private
lake. All conversion counts must reconcile before one atomic `case.json`
replacement commits the output catalog, source ledger and run record together.
Queries cannot see any of the new attempt before that commit.

The ledger combines canonical source path, host, kind, EVTX ANSI codec/raw
retention, ingest contract and SHA-256. Unchanged committed sources are skipped
and listed in `report.already_imported`; different hosts or decoding semantics
remain distinct. Committed partial sources keep their partial status. Retry
reparses failed-attempt input in a new workspace, not from byte checkpoints.

Legacy `lake/` files are adopted without rewriting. A one-time provenance-column
aggregation reconstructs path/host/SHA-256 entries; matching unchanged sources are
skipped under the default EVTX decoding and `keep_raw=False` policy, while auxiliary
sources are independent of that flag. Such entries are `legacy_unknown`, because
old rows cannot prove a complete parse. Existing duplicates are not repaired. Cleanup protects active
coordinators/workers, source evidence and committed output; inactive uncommitted
bulk data can be removed while retaining state/reports. This is process-interruption
atomicity, not a universal power-loss durability guarantee.

## Automatic small-file maintenance

After a successful ingest, local partitions with at least 128 files smaller than
8 MiB each are eligible for automatic compaction. Groups contain at most 256 MiB
of compressed input and share a 2GB/two-thread conversion budget. `c.compact()` or
`seclogx compact CASE` explicitly considers smaller groups of two or more small
files. Rows and schema must match before an atomic catalog replacement; compaction
does not remove repeated event rows.

Old physical files remain for registered `CaseDB` readers of the previous snapshot.
`c.cleanup_ingest()` reclaims retired managed `.ingest/` files only after those
readers close. Legacy `lake/` files are retained for older-reader compatibility.
Direct external DuckDB/file readers are not tracked; finish them before reclamation.
Budget for both old and new output during compaction. S3 automatic maintenance is
skipped and explicit S3 compaction is unsupported. Benefits depend on file sizes
and queries, not merely the number of files.

## Advanced deployment and diagnostic controls

The defaults use up to eight local parsing workers, 2GB of DuckDB managed memory
per conversion and two conversion threads. **2GB is not a whole-process or
Notebook RSS cap.** Native/Python allocations, Arrow buffers, parsing processes,
registry recovery, queries and independent background jobs require additional
memory. Change budgets for deployment constraints, not as a routine analysis step.

| `IngestOptions` setting | Meaning |
| --- | --- |
| `parser_backend="auto"` (default) | Use native where compatible, otherwise Python. |
| `parser_backend="python"` | Force Python compatibility parsing; automatic direct output is disabled. |
| `parser_backend="native"` | Fail when a recognized auxiliary source cannot use native parsing. Intended for diagnosis with compatible inputs. |
| `direct_parquet=None` (default) | Resolve the direct/staged path from the execution context. |
| `direct_parquet=False` | Force staging. |
| `direct_parquet=True` | Require local execution/storage, no broker, `keep_staging=False` and backend `auto` or `native`; incompatible configuration raises an error. |

On staged sources, `staging_format="auto"` uses Arrow IPC/ZSTD level 1 at
16 MiB or more and gzip NDJSON below that size. Explicit `"arrow"` / `"ndjson"`
override this. Native parsing on the staged path requires Arrow; strict native
mode needs `staging_format="arrow"` for small files too. EVTX follows the same automatic Arrow/NDJSON selection. Direct conversion has no staging-size threshold. The CLI exposes these
advanced overrides as `--parser-backend`, `--direct-parquet` /
`--no-direct-parquet`, and `--staging-format`; omission keeps automatic selection.

## Worker budgets and background ingest

`workers` is the **total local parsing budget** across EVTX and auxiliary pipelines, including explicit values. Mixed inputs split it; `workers=1` runs both pipelines serially in the calling process. The default is at most eight workers, and the local queue bounds pending tasks. Distributed workers are managed separately; this does not set a cluster-wide memory ceiling.

`CONVERSION_LOCK` serializes ingest conversions within one coordinator or Notebook process. Parsing may continue concurrently. Separate processes, background jobs and notebooks do not share the lock.

For detached execution, use this **instead of** the foreground import:

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"])
c.job_status(job_id)
```

The child uses the kernel's `sys.executable` and receives these ingest options.
Detaching frees the Notebook for other cells; it does not reduce the ingest's
work, memory or disk needs. Check for phase `done` or `failed` and inspect
`<case>/jobs/<job_id>.log` on failure. After `done`, reopen the case to query
with fresh views; an existing query connection is not refreshed by another
process. Background and foreground imports share catalog commits and safe whole-attempt retry.

Unchanged sources registered by this version are explicitly skipped on repeat; simultaneous duplicate starts still waste uncommitted work. See [Python API](06_python_api.md) for callbacks and script guards.

## Memory and disk boundaries

- Text-log and registry parsers emit completed records during ingest. Direct parser calls without `emit` retain the full-list API and its memory cost. Scheduled Task XML remains a whole-document parse, limited to 8 MiB by ingest. Registry uses a file-backed hive; transaction-log recovery through regipy and exceptionally large individual values remain memory exceptions.
- During auxiliary text ingest, SHA-256 and strict UTF-8 validation share one bounded full-file pass, followed by the parsing pass. UTF-16 requires a BOM or strong interleaved NUL/ASCII evidence; other non-UTF-8 sources try strict GB18030 then Latin-1 and may require more reads; QCloud requires a UTF-16 BOM. Validation completes before any record is emitted. File identity, size and timestamps are checked when reusing this preparation; this is not an immutable evidence snapshot. Direct parser calls outside ingest still validate their input independently.
- Physical text lines have an 8 Mi-character limit. Logical-record and format limits also apply, including QCloud's 4 Mi characters/100,000 lines, database limits and CSV field size. Oversized records produce explicit errors; see [known limitations](../known_limitations.md).
- `staging_chunk_bytes` targets **uncompressed bytes**: encoded NDJSON bytes for gzip, or Arrow batch buffer bytes for IPC. Gzip shards rotate between records with a bounded 256 KiB write buffer. Arrow uses record batches bounded by 16,384 rows and a 16 MiB size estimate, rotating shards between batches, plus a 1 MiB output buffer per active writer. One record can exceed a batch/shard target; encoded records above 32 MiB are rejected.
- Scratch paths are isolated under `.ingest/<id>/s_evtx/` and `.ingest/<id>/s_aux/`. Sources on the staged paths complete staging before flattening bounded shard groups. `flatten_batch_bytes` is a target, and an indivisible shard can exceed it. File/shard metadata grows with its count, and the full staged dataset can accumulate before conversion, including other formats and compatibility replays when direct conversion is enabled.
- Gzip and Arrow staging are **removed after successful conversion by default**. Automatic direct output skips these shards for compatible local sources; other sources can still accumulate a complete staged dataset before conversion. `keep_staging=True` retains intermediate files and selects staging. Source evidence is never deleted. Budget for source evidence, staging, Parquet and temporary working files together; cleanup does not eliminate peak staging usage.
- EVTX `keep_raw=True` uses temporary SQLite indexing instead of a whole-file XML dictionary. It still adds an XML parse, index I/O, larger output and temporary disk space; no fixed speed or memory multiplier is promised.
- The 2 GiB non-EVTX source-file exclusion has been removed. Supported large files reach their parser; record/document limits remain. A shared scan classifies both pipelines using bounded content peeks. Unknown files are reported without full hashing or parsing tasks.

DuckDB reads each bounded group into partitioned Parquet. Arrow staging feeds batches directly to DuckDB and avoids NDJSON serialization and reparsing between parsing and conversion. It still incurs Arrow construction/compression, reading, normalization and Parquet output costs.

Auxiliary staging also collects a bounded partition list, allowing Windows local storage to pre-create Hive directories without rereading all staged rows. Collection is limited to 4,096 partitions and 1 MiB of encoded partition values per source; a conversion group also falls back above 4,096 unique partitions. Legacy manifests, unsupported values or an exceeded bound retain the authoritative DuckDB `SELECT DISTINCT` scan. These limits disable the optimization, not the import. EVTX keeps its existing partition-discovery path; POSIX/object storage do not need the Windows directory pre-creation step.

Auxiliary conversion uses fixed VARCHAR input columns followed by canonical casts, without schema-inference sampling. Date-shaped free text therefore keeps its original spelling across different shard boundaries. Tomcat records exceeding 200 continuation lines are rejected before emitting the current entry; completed earlier records can remain in a partial file.

## EVTX integrity and analysis results

Recoverable EVTX iterator errors do not terminate the whole file; later valid
chunks are read. The hash pass audits structurally valid chunk-header record
counts and marks discrepancies partial. Corrupt headers and unexposed upstream
errors still limit this check; recovered counts are not proof of complete recovery
for arbitrary damage. Known ANSI source metadata uses `SourceSpec.ansi_codec`, with
an explicit `windows-1252` default; see [log types](02_log_types_and_schema.md#encoding-and-evtx-recovery).

EVTX Arrow removes the outer JSON staging encode/reparse while preserving rendered
JSON/XML and canonical SQL. The dependency still crosses the Python boundary per
record. Parquet uses ZSTD level 1. `keep_raw=True` still adds XML parsing and disk
indexing costs.

Hunt automatically retains complete results on disk. Small results keep `.matches`;
large results use `preview()`, `iter_chunks()` or `save()`. `total_matches` counts
all matches, and a preview never silently substitutes for complete results.

## Deployment diagnosis before changing parallelism

Use a fresh case when comparing configurations on representative evidence.
Keep the input and measurement boundaries consistent, and check recovered
records as well as speed. Measure:

- Total elapsed time/throughput and scan, staging and flatten durations.
- Peak RSS of the coordinator **and all workers**, plus system free memory.
- Peak staging/temporary disk usage and final Parquet size.
- Discovered/successful/partial/failed files and recovered/written records.

Start with `workers=1` for a tighter budget and change one setting at a time. More workers can increase disk contention and memory even with streaming. Lower DuckDB memory can increase spilling or fail conversion; reserve temporary disk space and inspect reported errors.

There is no byte-offset resume or immediate flattening with disk-space backpressure. Failed attempts remain invisible and are replayed on retry. Existing query connections retain a committed snapshot; reopen after another process imports. Retained shards are diagnostic material, not an alternative public commit interface.

After ingest, use filtered queries or `_chunks` accessors for large results. Unfiltered `.query()`/`.web_logs()` still materialize complete DataFrames; ingest options do not change query delivery. See [Querying & search](03_querying_and_search.md).

Next: [09. FAQ & limitations](09_faq_and_limitations.md).
