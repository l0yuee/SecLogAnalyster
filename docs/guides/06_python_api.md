# 6. Python / notebook API

**Language: English | [中文](06_python_api.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | 06. Python API | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

The Python API provides DataFrames, chunk iterators, ingest reports and job
status objects for Jupyter and scripts. For the
bounded-memory (`_chunks`) and `search()` memory-safety mechanics used
below, see [03. Querying & search](03_querying_and_search.md).

## Notebook environment

Prepare the project once using the [installation guide](01_getting_started.md#install),
including Rust/Cargo and the platform compiler for a source installation.
The normal project install includes the native parser. Then start Jupyter in
the dedicated environment:

```bash
conda activate python314
python -m jupyterlab
```

Select **Python (python314)** and check `sys.executable` in a cell. The guide
includes JupyterLab/ipykernel installation and kernel registration. Restart
existing kernels after rebuilding or upgrading the package. Background ingest
uses the selected kernel's interpreter.

## Import in a Notebook

```python
from seclogx import Case

c = Case.create("large_case")  # Case.open("large_case") in later sessions
report = c.ingest([r"E:\evidence:HOST01"])
print(report.summary_text())
```

No performance options are required. Compatible local UTF-8 Common/Combined
and IIS sources automatically use Rust parsing, bounded Arrow batches and
direct Parquet output. Other formats and incompatible input use Python
compatibility parsing. Source hashing, encoding checks and canonical SQL
normalization are retained. Normal installation includes the native extension;
if it cannot load at runtime, automatic mode falls back and records the reason.

The defaults are `parser_backend="auto"`, `direct_parquet=None` (automatic)
and `keep_staging=False`. Automatic direct conversion applies to local
execution and local storage without a broker. Retaining staging or using
distributed/object storage selects the staged path instead. Staging shards are
removed after successful conversion by default; source evidence is never
deleted. Pass `keep_staging=True` if intermediate files are needed for diagnosis.
This is a change from the earlier staging-retention default.

Use this call **instead of** foreground ingest to keep the Notebook available:

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"])
c.job_status(job_id)
```

Wait for `done`, inspect the log and file report, then reopen the Case for fresh
query views. `done` can include partial, failed or unknown sources. Captured
exceptions mark the job `failed`; a killed process can leave a stale status.
Logs and status snapshots are in `c.case_dir / "jobs"`; an unknown job returns
`None`. Foreground/background calls are alternatives: repeating the same import
can append duplicates. Neither mode provides automatic resume, early-query
guarantees or atomic visibility of the whole import.

When `report.aux` exists, `report.aux.to_dataframe()` includes
`parser_backend` / `backend_reason` for the actual parser and
`output_format` / `parquet_paths` for the output. Direct sources publish private
Parquet after closure and source checks; ordinary parsing errors can retain a
complete prefix with `partial` status. Other formats and compatibility replay
still stage before conversion. See [performance and scale](08_performance_and_scale.md).

## Advanced resource and diagnostic controls

`IngestOptions` is intended for deployment budgets and troubleshooting, not a
required analysis workflow. Defaults use at most eight local parsing workers,
`memory_limit="2GB"`, `threads=2`, 64 MiB staging targets and 256 MiB conversion
groups. **2GB is not a cap on Notebook or process-tree RSS.** Parser/Arrow/native
allocations, other queries and independent background jobs need additional
memory. `workers` is shared by EVTX and auxiliary parsers; `workers=1` runs
serially in the caller. Conversion threads are a separate budget.

| Override | Purpose |
| --- | --- |
| `IngestOptions(parser_backend="python")` | Diagnose a parser difference through the Python compatibility path; automatic direct output is disabled. |
| `IngestOptions(parser_backend="native")` | Require native support for each recognized auxiliary source; incompatible mixed inputs fail. |
| `IngestOptions(direct_parquet=False)` | Force staging for diagnosis. |
| `IngestOptions(direct_parquet=True)` | Require a compatible execution configuration; raises for retained staging, nonlocal storage, a broker, or Python-only parsing. Individual unsupported inputs still use compatibility replay in `auto`. |
| `c.ingest(sources, keep_staging=True)` | Keep intermediate shards and automatically use the staging path. Source files are unaffected. |

`staging_format="auto"` applies only to staged sources: at least 16 MiB selects
Arrow IPC/ZSTD, otherwise gzip NDJSON. `"arrow"` / `"ndjson"` force the format;
EVTX remains NDJSON. Strict native parsing on the staged path requires Arrow,
including for small files. Direct output has no small-file Arrow threshold.

After ingest, unfiltered `c.query()` and `c.web_logs()` still materialize whole
DataFrames. Filter first or consume `query_chunks()` / `web_logs_chunks()` one
batch at a time; ingest budgets do not bound analysis result size.

## General API examples

> **Calling `ingest()` from a `.py` script? Put it under an
> `if __name__ == "__main__":` guard.** Ingest stages files across worker
> processes started with Python's `spawn` method, and each worker
> re-imports your script -- without the guard, every worker re-runs the
> ingest instead of doing its share, and Python aborts the pool.
> `seclogx` raises `UnguardedMainError` telling you this if it happens.
> Notebooks, the REPL, and the `seclogx` CLI are unaffected, and
> `workers=1` (which stages in the calling process, no pool) works
> anywhere.
>
> ```python
> from seclogx import Case
>
> def main():
>     c = Case.create("incident42")
>     print(c.ingest(["/mnt/kape_output/WKS01:WKS01"]).summary_text())
>
> if __name__ == "__main__":
>     main()
> ```

```python
from seclogx import Case

# Create or open a case
c = Case.create("incident42")          # first time
# c = Case.open("incident42")          # use this instead in subsequent sessions

# Ingest (same semantics as the CLI; PATH or "PATH:HOST" strings)
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    on_progress=lambda snapshot: print(snapshot["phase"], snapshot.get("files_scanned", 0)),
)
print(report.summary_text())
report.to_dataframe()                  # per-file staging detail as a DataFrame (EVTX pass)
report.aux.to_dataframe()              # discovered auxiliary candidates and their statuses
```

`on_progress` receives phase, walked/classified/staged counts, file-status totals
and rows written by table. Updates are throttled at progress events (roughly
0.3 seconds or 25 completed files); this is not a heartbeat or byte-level ETA.
Keep the callback lightweight. A large file can run without changing the counters.

Alternatively, **replace** the foreground `c.ingest(...)` call above with a
background call. Do not run both against the same evidence:

```python
job_id = c.ingest_background(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
)
c.job_status(job_id)                   # dict snapshot, or None if absent
c.job_status()                         # most recently started job
c.list_jobs()                          # list[dict], most recently started first
```

The analysis examples below assume the chosen import has finished. Use filters
or the `_chunks()` alternatives for results that may exceed available memory.

```python
c = Case.open("incident42")

# Explore
c.summary()
c.channels()
c.hosts()
c.table_counts()                       # DataFrame: table name -> row count, for every table this case has

# Ad hoc SQL -> DataFrame
df = c.query("""
    SELECT time_created, computer, (event_data ->> 'Image') AS image
    FROM events
    WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
""")

# Not sure what's actually in a table, or which field to search on?
# fields() samples this case's data -- one row per field
# (real column or a sampled key inside a JSON catchall like event_data),
# how common it is, and a real example value. See "Which fields can I
# search on?" in 02. Log types & schema for the full explanation and a cheat sheet.
c.fields("events")       # -> Image, CommandLine, TargetUserName, ... (from event_data) + real columns
c.fields("web_logs")     # -> status, uri_stem, client_ip, ... (real columns)

# ...or the same thing without SQL: plain field/value conditions against
# any table. eq= exact, contains= fuzzy/substring, regex= regular
# expression; case-insensitive by default; different conditions combine
# with AND (match="any" for OR); multiple values for one field combine
# with OR. Field names work whether or not they're a "real" column --
# Image/CommandLine/etc. are looked up inside event_data automatically.
# See 03. Querying & search for the full explanation.
df = c.search(
    "events",
    contains={"Image": "mimikatz"},
    eq={"channel": "Microsoft-Windows-Sysmon/Operational"},
)
c.search("web_logs", contains={"uri_stem": "admin"}, eq={"status": [401, 403]})
c.search("events", regex={"CommandLine": r".*-enc.*"})

# search() refuses (raising ResultTooLargeError) rather than risking an
# out-of-memory crash if the estimated result is too large -- see
# "The memory-safety check" in 03. Querying & search for search_chunks()/
# search_to_csv(), the alternatives it points you at.

# Every log family is a first-class, DataFrame-returning accessor -- the
# same treatment `events` gets, so nothing requires raw SQL just to get a
# DataFrame. Each returns an empty (not erroring) DataFrame if the case
# has no data for it yet. See "Bounded-memory access for large tables" in
# 03. Querying & search before calling one of these unfiltered on a case
# with real-world web-log volume.
c.web_logs()                           # access logs: IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_logs(log_type="nginx")           # filtered to one engine
c.web_error_logs()                     # error logs: nginx/Apache/Tomcat/IIS HTTPERR
c.web_error_logs(log_type="apache")
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")
c.syslog()                             # generic syslog, incl. auth.log/secure content
c.auditd_logs()                        # Linux Audit Framework
c.journal_logs()                       # systemd journal export
c.db_logs(log_type="mysql_slow")       # MySQL/MariaDB, PostgreSQL, MSSQL, Oracle logs
c.qcloud_logs(log_type="ydservice")    # Tencent Cloud Host Security client logs
c.registry()                           # Windows Registry hives: SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/...
c.registry(hive_type="software")
c.suspicious_registry()                # high-entropy values + Run/services/COM/IFEO persistence heuristics

# The CaseDB convenience methods are available via c.db
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # full-text across event_data/provider/computer
c.db.tables                            # list[str]: which tables this case actually has
c.db.table("web_error_logs")           # generic escape hatch: any table by name, as a DataFrame

# Scheduled Task triage (heuristic, not Sigma -- see 04. Threat hunting)
c.suspicious_tasks()

# Auth event triage over syslog (heuristic, not Sigma): SSH accept/fail,
# sudo commands, PAM session open/close, account management
c.auth_events()

# Hunt
results = c.hunt()                      # or c.hunt(rules_dir=Path("..."), min_level="high")
results.matches                         # DataFrame: matched event rows + sigma_rule_id/title/level/attack ids
results.rule_summary                    # DataFrame: one row per rule evaluated, with match counts
results.skipped                         # list[(path, reason)] for unsupported-logsource rules
results.failures                        # list[RuleFailure] for conversion/execution errors
results.save("matches.csv")

# Timeline
tl = c.timeline(host="WKS01", event_id=[4624, 4625])

# Close the DuckDB connection cleanly
with Case.open("incident42") as c:
    df = c.summary()
```

## Method reference

| Category | Methods |
|---|---|
| Lifecycle | `Case.create(name, case_root=, cluster_config=)`, `Case.open(name, case_root=, cluster_config=)`, `Case.list_cases(case_root=)`, `c.info()` |
| Ingest | `c.ingest(sources, workers=, keep_raw=, keep_staging=, on_progress=, options=)` -> `IngestReport`; `c.ingest_background(sources, workers=, keep_raw=, keep_staging=, options=)` -> `job_id`; `c.job_status(job_id=)` -> `dict \| None`; `c.list_jobs()` -> `list[dict]` |
| Ingest resources | `IngestOptions(memory_limit="2GB", threads=2, staging_chunk_bytes=64 * 1024 * 1024, flatten_batch_bytes=256 * 1024 * 1024, staging_format="auto", parser_backend="auto", direct_parquet=None)` |
| Exploration | `c.summary()`, `c.channels()`, `c.hosts()`, `c.table_counts()` |
| Fields / no-SQL search | `c.fields(table, sample_size=)`, `c.search(table, eq=, contains=, regex=, match=, case_sensitive=)`, `c.search_chunks(...)`, `c.search_to_csv(table, path, ...)` |
| Raw SQL | `c.query(sql)`, `c.query_chunks(sql, chunksize=)`, `c.db.table(name)`, `c.db.table_chunks(name, chunksize=)` |
| Per-log-family accessors | `c.events()` / `c.events_chunks()`, `c.web_logs(log_type=)` / `_chunks`, `c.web_error_logs(log_type=)` / `_chunks`, `c.scheduled_tasks()` / `_chunks`, `c.exchange_message_tracking()` / `_chunks`, `c.exchange_logs(log_type=)` / `_chunks`, `c.syslog()` / `_chunks`, `c.auditd_logs()` / `_chunks`, `c.journal_logs()` / `_chunks`, `c.db_logs(log_type=)` / `_chunks`, `c.qcloud_logs(log_type=)` / `_chunks`, `c.registry(hive_type=)` / `_chunks` |
| Scheduled Task triage | `c.suspicious_tasks()` |
| Auth event triage (over `syslog`) | `c.auth_events()` |
| Registry triage | `c.suspicious_registry(entropy_threshold=7.0, min_size=32)` |
| Detection | `c.hunt(rules_dir=, min_level=)` -> `HuntResults` |
| Timeline | `c.timeline(start=, end=, host=, channel=, event_id=)` / `c.timeline_chunks(...)` |
| `CaseDB` (`c.db`) | `.tables`, `.table(name)` / `.table_chunks(name)`, `.sql(query)` / `.sql_chunks(query)`, `.by_event_id(ids)`, `.by_host(host)`, `.search(text)`, `.estimate(query)` -> `ResultSizeEstimate` |

## Distributed mode from Python

`Case.create()` and `Case.open()` resolve `ClusterConfig` from the environment
when the Case is constructed, unless given `cluster_config=` explicitly. Later
foreground `ingest()` and `hunt()` calls use the Case's stored configuration;
neither method accepts a `cluster_config` argument. Set the
`SECLOGX_BROKER_URL`/`SECLOGX_STORAGE_BACKEND`/`SECLOGX_S3_*` variables described in
[10. Distributed deployment](10_distributed_deployment.md) before creating or
opening the Case, or pass an explicit configuration to those factory methods.

`ingest_background()` starts a new CLI process that resolves cluster settings
from its inherited environment. An explicit in-memory `c.cluster_config` is not
serialized to that child; configure the environment before spawning background
work. The local `workers` budget does not control the size of a distributed queue.

Next: [07. Recipes](07_recipes.md) for worked, copy-pasteable examples
using this API (and its `seclogx search` no-SQL equivalents).
