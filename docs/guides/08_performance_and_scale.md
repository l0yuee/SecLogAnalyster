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
- Scheduled Tasks/IIS/web access/Exchange logs are parsed straight to
  Python dicts per file (no intermediate NDJSON staging), and unlike the
  EVTX pipeline, **ingest for these log families is not yet
  bounded-memory**: a single ingest run accumulates every parsed row for
  a given table in memory across the whole batch before writing Parquet.
  Fine at the volumes exercised so far; a single ingest run processing
  enough files to reach terabyte scale *in one batch* could exhaust
  memory during ingest even though querying the resulting lake afterward
  would be fine. This is specifically an ingest-time boundary, separate
  from (and not fixed by) the query-side chunking above -- see
  `docs/known_limitations.md`.

Next: [09. FAQ & limitations](09_faq_and_limitations.md) for
troubleshooting and the full known-limitations pointer.
