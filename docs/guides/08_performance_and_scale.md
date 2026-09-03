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
- Ingest parallelism (`--workers`) scales with CPU cores -- files are
  parsed independently in separate processes (or, in distributed mode,
  across `seclogx worker` processes on any number of machines).
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
- Scheduled Tasks/IIS/web access/Exchange/syslog/auditd/journal logs now
  stage to per-file NDJSON the same way EVTX does, and flatten via DuckDB
  reading straight off disk (`read_ndjson_auto`) instead of accumulating
  every parsed row for a table in Python across the whole batch. Peak
  ingest-time memory is now bounded by (one file's parse footprint) x
  `workers`, not by total batch size -- a batch large enough to reach
  terabyte scale no longer has to fit in memory at once during ingest.
  Per-file parsing itself (needed for encoding detection) still reads a
  whole file at a time, so a single pathologically large individual file
  is still a per-file, not per-batch, memory cost.
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
  hashing.

Next: [09. FAQ & limitations](09_faq_and_limitations.md) for
troubleshooting and the full known-limitations pointer.
