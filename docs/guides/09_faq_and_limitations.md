# 9. Troubleshooting, FAQ, and known limitations

**Language: English | [中文](09_faq_and_limitations.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | 09. FAQ & limitations | [10. Distributed deployment](10_distributed_deployment.md)

---

## Troubleshooting / FAQ

**"case '&lt;name&gt;' has no ingested data yet -- run `ingest` first"**
You created/opened a case but haven't successfully ingested anything
into it yet (or every source file failed to parse). Run `seclogx ingest`
and check the reconciliation report for errors.

**A query mentions a column that doesn't exist**
Provider-specific fields live inside `event_data`, not as top-level
columns -- use `event_data ->> 'FieldName'`, not `FieldName` directly.
See `docs/schema.md` for the full list of real top-level columns.

**A hunt reports rules under "failed"**
Run `seclogx rules validate --rules <dir>` against the same rules
directory to see the exact conversion/field-mapping error per rule, then
see "Extending detection" in [04. Threat hunting](04_threat_hunting.md).

**An ingest run shows files as `partial`**
This can occur with damaged EVTX files, rejected text records or a parser
error after valid records were recovered. Inspect the per-file record count,
error count and error message before deciding whether the result is usable.
A staging write or flush failure is fatal, not a successful partial parse.

**`ingest` seems slow on a huge single file**
Parsing parallelism is per source file: a single large source is not split
across workers. More workers help only when there are independent files and
enough memory/I/O capacity. EVTX `--keep-raw` adds XML parsing and temporary
SQLite indexing; its cost is workload-dependent. Check the reported staging
and conversion phases before tuning; see [Performance & scale](08_performance_and_scale.md).

**I want to re-run ingest after fixing something**
Ingest appends records. Repeating the same source can duplicate data, and a
failed conversion can leave some Parquet output. There is no automatic
resume, deduplication or transactional rollback. Use a fresh case when
rebuilding the same evidence. Retained NDJSON/Arrow shards help diagnose a
failure; calling internal flatten functions is not a supported resume protocol.

**Jupyter stays busy, or the kernel uses the wrong Python environment**
Activate `python314` before starting local Python or JupyterLab and verify the
selected kernel's `sys.executable`. `c.ingest()` blocks until it completes;
`c.ingest_background(sources)` starts a detached child
using that interpreter. Poll `c.job_status(job_id)` and inspect
`<case>/jobs/<job_id>.log` on failure. After phase `done`, reopen the case for
fresh query views. Background execution does not reduce memory requirements
or implement recovery; avoid concurrent writes to the same case.

**Why are there `.arrow` files, and why is staging still large?**
Compatible local Web/IIS sources automatically bypass staging. Other sources
use `staging_format="auto"`: Arrow IPC/ZSTD at 16 MiB or more, gzip NDJSON below
that; EVTX remains NDJSON. These sources still finish staging before conversion,
so temporary disk usage can grow with the staged dataset. Successful conversion
removes those shards by default. `keep_staging=True` retains intermediates and
selects staging; it never deletes source evidence. Reserve source, staging,
Parquet and temporary space even with automatic cleanup.

**A file I expected to be ingested shows up under "files unrecognized"**
Its content didn't match any supported format's detection (see the
known-limitations section below). Common causes: a custom nginx/Apache
`log_format` that isn't Common/Combined Log Format, a truncated IIS/
Exchange header missing its `#Fields:` line, or a genuinely unsupported
file that happened to be under the source path. Check
`AuxIngestReport.unknown_samples` (or the ingest summary's sample list)
for the exact path.

**A web access log's `log_type` shows `web_access` instead of `nginx`/`apache`/`tomcat`**
Common/Combined Log Format is identical across all three servers; the
label is a best-effort path/filename heuristic, not a detection. `web_access`
just means no hint was found -- the data itself is unaffected.

**`seclogx hunt` reports a rule as "case has no '&lt;table&gt;' table ingested"**
That rule's logsource category targets a table (`events` or `web_logs`)
this case hasn't ingested any data into yet -- not a conversion error.
Check `seclogx sources <case>` to see what the case actually has.

**A query against a large table (`web_logs` especially) uses too much memory or is slow to return**
`c.query()`/`c.table()`/`c.web_logs()`/etc. fetch the entire result as one
DataFrame. Switch to the `_chunks` sibling (`c.query_chunks()`,
`c.web_logs_chunks()`, ...) and iterate -- see "Bounded-memory access for
large tables" in [03. Querying & search](03_querying_and_search.md). If
you're using the CLI, `--out`/the console preview already use the
chunked path automatically; if it's still slow, check whether your
query's `WHERE` clause is actually selective (an unfiltered `SELECT *
FROM web_logs` still has to read the whole table, chunked or not --
chunking bounds *memory*, not the amount of data scanned).

**`Case.search()` raised `ResultTooLargeError`**
Not a bug -- the estimated result was judged too large for this
machine's available memory to safely hold as one DataFrame. The error
message names the estimated row count/size; use `search_chunks()` to
iterate the same search in bounded-size pieces, or `search_to_csv()` to
stream every matching row straight to a file. On the CLI, `seclogx
search` never raises this -- it always shows a bounded preview and warns
in the same situation, telling you to add `--out` instead.

**`seclogx search` / `Case.search()` says a field "is not a column ... and this table has no JSON field to search inside either"**
The field name isn't one of the table's real columns, and the table has
no JSON-object catchall to look inside either (for example, the bundled
`scheduled_tasks` and `registry` tables -- see "Searching without
SQL" in [03. Querying & search](03_querying_and_search.md)). The error
message lists the table's actual column names. If you're trying to
search inside `actions`/`triggers` specifically, search that column
directly with `--contains`/`--regex` (whole-column text match) rather
than a field name nested inside it -- those are JSON *arrays*, not
objects, so keyed extraction doesn't apply.

## Known limitations

The complete, current list of v1 scope decisions and known
edge cases lives in **`docs/known_limitations.md`** -- treat
that file as the source of truth (it's kept current as the project
evolves; this section is not a substitute for it). Highlights most
likely to come up in day-to-day use:

- `UserData`-based providers (some RDP/Task Scheduler/Defender events)
  are stored and full-text searchable, but not yet field-mapped for
  Sigma hunting the way `EventData`-based providers are.
- Sigma logsource categories route to their **Sysmon** equivalents, not
  native Security-channel equivalents (e.g. process creation -> Sysmon
  EventID 1, not Security 4688).
- Non-EVTX format detection is content-based, not guaranteed --
  nonstandard log headers can be misclassified as unrecognized (reported,
  never silently dropped).
- Ingest emits text/registry records to bounded staging batches rather than
  retaining all rows of each source. Whole-document Scheduled Task XML,
  registry recovery and large individual values remain exceptions. Worker
  count multiplies parser/buffer costs; `memory_limit` controls one DuckDB
  conversion's managed memory, not total RSS. See
  [08. Performance & scale](08_performance_and_scale.md).
- Parsing and conversion do not yet form a disk-backpressured pipeline.
  Automatic resume, cross-run idempotency and atomic lake commits/snapshots
  are not implemented. Metadata locks do not make concurrent ingest transactional.
- `.query()`/`.table()`/`.web_logs()`/etc. materialize the full result as
  one DataFrame; use the `_chunks` sibling for anything not already
  filtered/aggregated down to something small (see
  [03. Querying & search](03_querying_and_search.md)).

For everything else -- Exchange/web-log format coverage, Scheduled Task
format support, Sigma feature coverage, `search()`'s exact matching
semantics and memory-estimate caveats, and more -- see
`docs/known_limitations.md` directly.
