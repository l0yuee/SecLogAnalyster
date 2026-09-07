# 8. Performance and scale notes

**Language: English | [中文](08_performance_and_scale.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | 08. Performance & scale | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

- Designed for one workstation by default -- no setup, no external
  services required. An opt-in, environment-variable-activated
  distributed mode also exists (see
  [10. Distributed deployment](10_distributed_deployment.md)): it helps
  when an ingest batch is large enough that spreading file-parsing across
  machines saves real wall-clock time, when a Sigma rule set is large
  enough that rule-by-rule evaluation on one machine is the bottleneck, or
  when multiple analysts want to query one shared case concurrently
  without each holding a local copy of it. It does **not** help a single
  query or a single small case -- query execution is always single-node
  DuckDB, distributed or not; see that guide for the exact boundary.
  Within all of this, individual log families vary widely in realistic
  volume: EVTX cases are typically well under 100GB, while web access/
  error logs across a case can realistically reach terabyte scale.
- Ingest parallelism (`--workers`) uses at most eight local processes by
  default -- files are parsed independently, but parser-process memory and
  concurrent evidence-disk reads make unconstrained CPU-count parallelism
  counterproductive on many workstations. Set `--workers` explicitly to tune
  for fast NVMe storage or a tighter memory budget. Distributed mode still
  fans work out across the available `seclogx worker` processes.
- The source tree is walked **once**, not twice. Before this was fixed,
  `ingest` discovered `.evtx` files with one single-threaded tree walk,
  then discovered and content-classified every other file with a
  *second*, separate single-threaded tree walk -- for a real evidence set
  (thousands of small/mixed files, some of them not a supported log type
  at all), that second pass alone -- one Python loop, one thread, a 16KB
  read plus a chain of regexes per candidate file (`sniff.classify_file`)
  -- was the actual dominant wall-clock cost, not per-file parse
  throughput, and it produced no output the entire time it ran.
  `ingest.scan.scan_sources()` now walks each `--source` root exactly once
  and classifies the non-`.evtx` candidates' content in parallel with a
  thread pool (that peek is I/O-bound, so threads scale it even though
  CPU-bound parsing needs separate processes). The `.evtx` pass and the
  non-`.evtx` pass then run **concurrently** rather than back-to-back,
  each still managing its own bounded worker pool -- when both have work
  and `--workers` wasn't pinned explicitly, the default worker budget is
  split between them rather than doubled, so peak concurrent worker
  processes (and therefore peak memory) doesn't grow versus running one
  pipeline at a time.
- That single walk uses `os.scandir` rather than `Path.rglob("*")` plus
  `is_file()`, `resolve()` and `stat()` per entry. The latter costs three
  or four syscalls per file (plus `resolve()`'s per-path-component
  readlink walk) where scandir gets the entry type from the directory read
  itself and needs one stat: **measured 4.6x faster on a 24,000-file
  acquisition tree** with a warm cache, and the gap widens on cold,
  network-mounted or spinning storage where syscall count dominates.
  Cross-source dedup is now keyed by `(st_dev, st_ino)` from that stat
  rather than by resolved path, which costs nothing extra and also catches
  hard links. Symlink behavior is unchanged: a symlink to a log file is
  followed and ingested, a symlinked *directory* is not descended into
  (so a symlink cycle can't hang the walk). The walk also reports a
  running file count as it goes, so the very first phase of a large ingest
  is no longer silent.
- Staging a parsed file writes its NDJSON through **one reused
  `json.JSONEncoder`**. `json.dumps(row, ...)` with any non-default
  keyword argument builds a fresh encoder per call and skips the module's
  cached one, which profiling put in the top three costs of a
  600k-row ingest. Combined with a hand-rolled Common Log Format
  timestamp parser (`ingest/logsources/parsers/webaccess.py`) that reads
  the fixed-width shape by slicing instead of `datetime.strptime` --
  4.5x faster on that call, which happens once per access-log line, with
  `strptime` kept as the fallback for unusual-but-valid variants -- this
  cut **per-file staging CPU by ~22%** on the same benchmark.
- `ingest` shows a **live progress display** in the foreground (current
  phase, files scanned so far, staged ok/partial/failed/unsupported
  counts, rows written per table) instead of producing no output until
  the whole run finishes. `--background`/`-b` detaches the import into a
  separate process and returns immediately, printing the exact
  `seclogx ingest-status <case> --watch` command to check on it --
  useful for a large import an analyst doesn't want to babysit at a
  terminal. Status is a small JSON snapshot at
  `cases/<name>/jobs/<job_id>.json`, updated (throttled, not on every
  single file) as the job runs and written atomically so a concurrent
  `ingest-status` read never sees a half-written file; the background
  job's captured stdout/stderr lands in the sibling `.log` file. See
  [05. CLI reference](05_cli_reference.md).
- Flattening staged NDJSON into Parquet makes **one** pass over the data,
  not two. DuckDB's `COPY ... PARTITION_BY` creates the Hive partition
  directories itself, but two concurrent writers creating the same new
  directory can race on Windows, so the partition values used to be
  enumerated (`SELECT DISTINCT`, a full extra read and JSON-parse of every
  staged file) and their directories pre-created before every COPY.
  Measured at **~32% of flatten time**, paid on every platform to fix a
  Windows-only race; it is now gated on
  `StorageBackend.precreates_partition_dirs`, true only for local storage
  on Windows. POSIX mkdir races are already benign and object storage has
  no directories at all.
- Querying and hunting run through DuckDB directly against the
  Hive-partitioned Parquet lake, which gives lazy, out-of-core execution
  with predicate pushdown: a query filtered to one host/channel/event
  range only reads the Parquet row groups it actually needs, not the
  whole lake into memory. That said, *fetching* a large unfiltered result
  still defaults to one in-memory DataFrame (`.query()`/`.table()`/
  `.web_logs()`/etc., via DuckDB's `fetchdf()`) -- for a table or query
  that isn't already filtered/aggregated down to something small, use the
  `_chunks` sibling instead (`.query_chunks()`, `.web_logs_chunks()`,
  `.timeline_chunks()`, ...), which bounds memory by `chunksize` rather
  than total result size. See "Bounded-memory access for large tables" in
  [03. Querying & search](03_querying_and_search.md) for the full
  explanation and a worked example; the CLI (`query`/`table`/`tasks`/
  `timeline`) uses this automatically for both `--out` and the console
  preview, so no CLI flag is needed to get the bounded-memory behavior
  there.
- `.auth_events()` narrows `syslog` down to auth-shaped rows **in SQL**
  before pulling anything into pandas (see `AUTH_EVENT_CANDIDATE_SQL`),
  rather than materializing the whole table and filtering it row by row.
  syslog is one of the families that realistically reaches many millions
  of rows, of which SSH/sudo/PAM/account-management lines are a small
  fraction, so the old shape risked exhausting memory on exactly the cases
  where the view is most useful. The SQL filter is deliberately a strict
  *superset* of what the heuristic accepts, so the result is identical --
  pinned by a test that compares it against running the heuristic over the
  full table.
- `.search()` estimates a result's size before fetching it (`count(*)`,
  exact, plus a bytes-per-row figure from a small `LIMIT`-bounded sample,
  extrapolated to the full row count -- both steps bounded regardless of
  the table's total size, so the estimate itself never risks the memory
  it's trying to protect) and compares it against a quarter of the
  machine's actual currently-available memory, refusing rather than
  fetching if that's exceeded. Available memory is detected best-effort
  (`/proc/meminfo` on Linux, coarser fallbacks elsewhere) and falls back
  to a fixed 200MB assumption if it can't be determined at all, rather
  than assuming the machine has unlimited memory. See "The memory-safety
  check" in [03. Querying & search](03_querying_and_search.md).
- `--keep-raw` roughly doubles ingest cost (time and peak memory) for
  the files it's applied to -- use it selectively on evidence that
  needs full XML fidelity, not by default on an entire large case.
- Scheduled Tasks/IIS/web access/Exchange/syslog/auditd/journal/database/
  Tencent Cloud/registry logs stage to per-file NDJSON the same way EVTX does, and flatten via DuckDB
  reading straight off disk (`read_ndjson_auto`) instead of accumulating
  every parsed row for a table in Python across the whole batch. Peak
  ingest-time memory is now bounded by (one file's parse footprint) x
  `workers`, not by total batch size -- a batch large enough to reach
  terabyte scale no longer has to fit in memory at once during ingest.
  Tencent Cloud client logs use a one-record look-behind and stream directly
  into gzip staging, so their memory use is independent of file size while
  still preserving multiline records. Several other non-EVTX formats still
  read one whole file at a time, so a pathologically large individual file in
  one of those families remains a per-file, not per-batch, memory cost.
- Staged NDJSON (`staging/`, `staging_aux/`) is gzip-compressed (level 1)
  rather than written as plain text, and is kept by default (see
  `--keep-staging` in [05. CLI reference](05_cli_reference.md)) so a case
  can be cheaply re-flattened without re-parsing evidence. Rendered-as-JSON
  EVTX records in particular run considerably larger than the source
  binary `.evtx` -- uncompressed and kept, this combination is what makes
  a case directory land at several times the source evidence size rather
  than a fraction of it; gzip brings the staging directory back down close
  to (often smaller than) source size, at a compression cost that's small
  next to the parsing work already happening in the same worker, and read
  back transparently by DuckDB's `read_ndjson`/`read_ndjson_auto` with no
  meaningful decompression overhead. If disk is still tighter than time,
  `--no-keep-staging` drops the staging directory entirely once flattening
  succeeds -- the tradeoff is losing cheap reprocessing (a schema fix or a
  botched flatten then needs re-ingesting the source files, not just
  re-running the flatten step).
- Non-log content mixed into a source directory (PE/ELF binaries, memory
  dumps, etc.) is cheap to rule out: known-binary extensions
  (`.exe`/`.dll`/`.sys`/...) are skipped by extension before any file
  read, and anything else goes through a 16KB content peek
  (`sniff.classify_file`) to decide whether it's a supported format --
  never a full-file read for classification. A file that doesn't match
  any supported format (reported in `AuxIngestReport.unknown_samples`,
  never silently dropped) is never hashed or staged either, since neither
  is used for a file with no table to attach provenance to; only files
  that actually match a supported format pay the cost of a full read for
  hashing. Unknown files are also reported locally and never submitted as
  process-pool/distributed jobs; this matters for software acquisition trees
  containing thousands of executables beside a small number of actual logs.

Next: [09. FAQ & limitations](09_faq_and_limitations.md) for
troubleshooting and the full known-limitations pointer.
