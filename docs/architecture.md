# Architecture

seclogx preserves Python/Jupyter analysis interfaces and uses Rust parsing,
Arrow batches, DuckDB SQL and partitioned Parquet underneath. Supported families
and canonical columns are listed in [schemas](schema.md) and the
[log guide](guides/02_log_types_and_schema.md).

## Discovery and decoding

`Case.ingest()` scans sources once. Physical file identity deduplicates overlapping
paths with the same host label; different hosts remain distinct evidence. EVTX ANSI
metadata also participates in identity. Auxiliary classification reads a bounded
16 KiB prefix; unknown files are reported without a full hash or parser task.

UTF-16 requires a BOM or strong asymmetric NUL/ASCII byte-lane evidence. Even byte
length alone is never sufficient. Prefix decoding tolerates a final incomplete
multibyte character and precedes binary-density/XML checks. Without UTF-16 evidence,
strict UTF-8 and GB18030 precede Latin-1; QCloud requires a UTF-16 BOM.
BOM-less all-non-ASCII text remains ambiguous. Text preparation combines hashing
with ordinary UTF-8 validation, with extra passes for fallback encodings. Source
identity, size and timestamp checks detect ordinary changes, not arbitrary
manipulation of an immutable acquisition snapshot.

Aegis client logs require a supported core/Python header plus product context
from the path or content. Plain-text `data.N` and `data.<number>.N` rotations
follow the same classification path. Client/monitor headers without a severity
retain a NULL severity rather than inferring a level. Their streaming parser keeps complete multiline records,
including blank lines, and adds only recognized task-lifecycle fields to
`aegis_logs`; it does not execute Python payload text or decode private binary
formats. A logical record is limited to 4,194,304 characters and 100,000 lines.
These sources use the ordinary automatic Arrow/NDJSON staging path.

## Parsing and bounded staging

The default is at most eight local parsing workers shared by both pipelines.
`workers=1` executes serially. Pending tasks are bounded and only manifests cross
processes. Compatible UTF-8 Common/Combined and IIS W3C sources use the bundled Rust
extension automatically. It releases the GIL and constructs Arrow buffers without
per-record Python dictionaries crossing the native boundary. Unsupported input
uses Python compatibility parsing; explicit backend overrides remain diagnostic.

Compatible Web/IIS input streams directly to DuckDB with local execution/storage,
no broker and no retained staging. Other auxiliary sources finish staging and
close their pool before direct sources run sequentially in the coordinator.
Capability fallback deletes that source's private native output before complete
Python replay. Source changes, I/O failures and malformed native batches are fatal.

Staged auxiliary and EVTX sources automatically use Arrow IPC/ZSTD level 1 at
16 MiB or more and gzip NDJSON below that size. Arrow batches target 16,384 rows
and a 16 MiB conservative estimate; an indivisible record may exceed the target.
Shards target 64 MiB uncompressed; encoded records above 32 MiB are rejected.
Explicit native auxiliary staging requires Arrow; direct output has no size
threshold. `staging_format` is an advanced diagnostic override.

Text and Registry ingest emit records. Direct parser APIs without an emitter can
still return complete lists. Physical text lines are limited to 8 Mi characters;
logical-record limits also apply. Scheduled Task XML uses an 8 MiB document limit.
Registry recovery and unusually large values remain memory exceptions. See
[known limitations](known_limitations.md).

## EVTX recovery and source ANSI metadata

EVTX already uses the Rust `evtx` dependency. Each worker assigns one native
thread, avoiding an extra all-core pool per process. Recovery continues after
recoverable iterator errors, allowing later valid chunks to be read. I/O failures,
source changes and memory exhaustion remain fatal. A finite physical-input bound
prevents a broken iterator from raising forever without advancing.

The SHA pass also audits structurally valid chunk headers using physical record
ordinals, not event IDs. Recovery-count discrepancies produce `partial`, including
detectable record loss suppressed internally by the dependency. Header checks
cannot prove that every damaged record was exposed or recoverable. Manifests
record recovered/error counts and `header_record_count`.

EVTX does not reliably identify its source ANSI code page. The explicit default
is `windows-1252`, independent of the analyst's OS locale. Known source metadata
can be supplied using `SourceSpec(path, host, ansi_codec="gbk")`; `cp936` is an alias.
`ansi_codec` and `ansi_codec_source` record the decision. Unicode fields are
unaffected. This is evidence metadata, not a performance choice.

`keep_raw=True` adds an XML pass and a temporary disk-backed SQLite index, then
attaches XML by event record ID during JSON recovery. Missing XML/recovery errors
are reported; storage failures abort. Arrow preserves rendered JSON/XML and removes
the outer NDJSON serialization/reparse. It does not remove the dependency's
per-record Python boundary or JSON rendering.

## Canonical conversion

DuckDB converts bounded shard groups (256 MiB target) with fixed raw input types
and canonical SQL. EVTX Arrow record IDs are explicitly cast to BIGINT. Manifest
joins attach provenance. Parquet uses ZSTD level 1 and each table's Hive partitions.
Windows pre-creates partition directories. Auxiliary manifests avoid rereads with
bounded partition metadata (4,096 values/1 MiB per source), otherwise a scan is
retained. EVTX retains its partition scan, reopening its Arrow reader before COPY.
Staged and written counts must agree before cleanup or success.

`CONVERSION_LOCK` serializes conversions within one coordinator. Defaults are
DuckDB `memory_limit="2GB"` and `threads=2`. Managed conversion memory is not total
RSS, Windows private bytes, parser memory or pandas results. Separate jobs have
separate budgets; ordinary query connections do not inherit ingest settings.

## Atomic catalog and retry

Each attempt writes isolated `.ingest/<id>/` output. One atomic `case.json`
replacement commits exact Parquet filenames, source ledger and run history
together. Uncommitted output is invisible. Direct source publication remains
inside the private attempt; a later failure cannot expose a partial new batch.

Identity combines canonical path, host, detected kind, EVTX ANSI codec, EVTX raw
retention, ingest contract and SHA-256. Unchanged committed sources are skipped
and listed in `report.already_imported`. Different hosts/decoding semantics remain
distinct. Committed partial sources retain their partial status. Rows repeated
inside a source file are not deduplicated.

Legacy `lake/` files are adopted without rewriting. A one-time DuckDB aggregation
of their provenance columns reconstructs path/host/SHA-256 entries. Unchanged
sources can then be skipped for the default EVTX decoding and `keep_raw=False`
policy (auxiliary sources are independent of that flag). The status is explicitly
`legacy_unknown`: existing rows do not prove the old parse was complete. Alternate
EVTX code pages or raw retention are distinct imports. Existing duplicate rows
are not removed. Missing required provenance prevents automatic adoption for
further ingest; the old Case can still be opened for analysis.

Failed attempts replay in a fresh workspace, not from byte-offset checkpoints.
Cleanup removes inactive uncommitted bulk output while retaining state/report
metadata. Coordinator ownership and worker leases protect active writers,
including surviving workers after coordinator exit. Remote ownership/configuration
is not guessed; source evidence and committed output are excluded. Concurrent
commits serialize metadata and reject a source another attempt committed first.
This addresses process interruption and reported I/O failures, not universal
power-loss durability or a distributed SQL transaction.

## Small-file compaction

After a successful ingest, local maintenance automatically considers partitions
with at least 128 files smaller than 8 MiB each. It groups at most 256 MiB of
compressed input per conversion, using one 2GB/two-thread DuckDB budget.
`Case.compact()` or `seclogx compact CASE` explicitly considers groups of two or
more small files. Rows and schema are checked before an atomic catalog swap.
Compaction does not change the provenance/ledger or deduplicate event rows.

Original files remain available to existing registered `CaseDB` snapshots.
`Case.cleanup_ingest()` can reclaim retired managed `.ingest/` files after no
registered reader holds them. Legacy `lake/` files are retained for compatibility
with older readers. Direct external DuckDB/file readers do not register leases;
finish them before requesting reclamation. S3 automatic compaction is skipped,
and explicit S3 compaction is unsupported. Compaction can temporarily require
both input and replacement output space; no universal speedup is promised.

## Query and detection

`CaseDB` captures one committed catalog and creates views with
`read_parquet(..., hive_partitioning=true, union_by_name=true)`. Existing readers
keep that snapshot. Reopen after independent/background ingest; foreground ingest
resets its own cached connection.

Whole-result query/table methods create complete pandas DataFrames. Their
`_chunks` siblings bound delivered batches when callers release them; wide records
and joins/sorts still require memory. `search()` estimates before eager delivery;
chunked search and CLI exports stream.

Sigma compilation validates fields/identifiers, and execution accepts one read
query on a restricted connection. Complete hunt results are stored in Parquet,
not accumulated without bounds in pandas. Small hunts retain `.matches`; large
hunts use `preview()`, `iter_chunks()` or `save()`. `total_matches` is the complete
count, not preview length. See [hunting](guides/04_threat_hunting.md).

## Workspace and distributed storage

```text
cases/<name>/
  case.json                   # committed catalog, ledger and history
  .ingest/<id>/
    state.json, report.json   # ownership and source outcomes
    s_evtx/, s_aux/            # staging, removed by default
    _ingest_private/          # direct conversion scratch
    lake/<table>/...parquet   # visible only through committed catalog
    logs/                     # reconciliation summaries
  lake/<table>/...parquet     # legacy output adopted without rewriting
  jobs/                       # background state and logs
  hunts/                      # complete hunt results
```

S3 transaction output uses `s3://<bucket>/<name>/ingest/<id>/lake/`. Metadata,
staging and leases remain on a shared local/NFS case directory. RQ distributes
independent file/rule jobs, not a single DuckDB query. Redis coordinates distributed
metadata commits; local cases use file locks. Credentials follow the provider's
normal chain. See [distributed deployment](guides/10_distributed_deployment.md).

Staged input still completes staging before conversion; there is no general
disk-space backpressure pipeline overlapping them. Temporary space can grow with
all staged input. Resource targets do not guarantee fixed throughput.
