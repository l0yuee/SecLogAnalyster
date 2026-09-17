# 6. Python / notebook API

**Language: English | [中文](06_python_api.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | 06. Python API | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

The Python API provides DataFrames, chunk iterators, ingest reports and job
status objects for Jupyter and scripts. For the
bounded-memory (`_chunks`) and `search()` memory-safety mechanics used
below, see [03. Querying & search](03_querying_and_search.md).

## Notebook environment

Use the project's dedicated conda `python314` environment, isolated from `base`:

```bash
conda activate python314
python -m pip install -e .
python -m jupyterlab
```

JupyterLab and `ipykernel` must be installed in that environment to use these
commands. If the kernel is not listed, register it with
`python -m ipykernel install --user --name python314 --display-name "Python (python314)"`.
Choose this kernel and check `import sys; print(sys.executable)` in a cell.
For noninteractive scripts use `conda run --no-capture-output -n python314 python ...`.
Background imports spawn the current interpreter, so selecting the correct
Notebook kernel also selects their Python environment.

## Resource controls for a large Notebook import

```python
from seclogx import Case, IngestOptions

c = Case.create("large_case")  # use Case.open("large_case") in a later session
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

The `IngestOptions` values above are the library defaults; `workers=2`
explicitly sets parsing parallelism. `workers` is the total local parsing budget
across both pipelines; `workers=1` runs them serially in this process.
`threads` and `memory_limit` apply to each DuckDB conversion, and conversions
in one Notebook process are serialized; independent background jobs have separate
budgets. These options configure ingest conversion, not later analyst queries.
**2GB is not a hard RSS limit** for
the kernel or its worker processes. The byte settings target uncompressed
staging shards and conversion groups, with records/shards left indivisible.

`staging_format="auto"` selects Arrow IPC with ZSTD level 1 for each supported
auxiliary source of at least 16 MiB, and gzip NDJSON for smaller sources.
Set `"arrow"` or `"ndjson"` to choose explicitly. EVTX staging remains NDJSON;
auxiliary Parquet output uses ZSTD level 1 with either staging path. Both paths
retain fixed text input columns and the same canonical SQL normalization.

If the workstation has enough spare memory and CPU capacity, an optional configuration is
`IngestOptions(memory_limit="4GB", threads=8, staging_format="auto")` with
`workers=8`. This changes the budget, not the library defaults or a process RSS
limit. Leave room for the Notebook, parsing workers and other programs.

For background execution, replace the foreground call with
`job_id = c.ingest_background([r"E:\evidence:HOST01"], workers=2, options=options)`
and inspect `c.job_status(job_id)`. Do not run both imports on the same
evidence: cross-run deduplication/resume is not implemented. Staging remains
enabled by default; `keep_staging=False` deletes it after successful
conversion but does not remove its peak disk requirement. See
[Performance & scale](08_performance_and_scale.md) for parser limits,
encoding-validation I/O and resource limits.

Each pipeline stages its batch before conversion. Background execution does not
provide an early-query guarantee or an atomic snapshot of the lake while it is
being written. Wait for `done`, inspect the job log and per-file report, then
reopen the Case before analysis. `done` can include partial, failed or unrecognized
source files. Caught job exceptions set `failed`; forced termination or failed
status writes can leave a stale snapshot, because there is no separate liveness
supervisor or automatic resume. Status and stdout/stderr live under
`c.case_dir / "jobs"`. `job_status()` returns `None` if the requested job is not
found. Reopening avoids stale cached views in a `Case` object that existed before
the background import.

The corresponding CLI accepts `--staging-format auto` (or `arrow`/`ndjson`),
including with `--background`. During auxiliary text ingest, SHA-256 and strict
UTF-8 validation share a pass; alternate encodings retain strict fallback reads.
Bounded partition metadata also avoids the usual extra Windows partition scan
when complete; legacy, unsupported or oversized metadata falls back to scanning.

After importing, an unrestricted `c.query()` or `c.web_logs()` still builds one
complete DataFrame and can exhaust the Jupyter kernel's memory. Filter in SQL or
consume `c.query_chunks()` / `c.web_logs_chunks()`; ingest options do not limit
the size of returned DataFrames. Chunks are bounded in rows, not bytes: choose
`chunksize` for your record widths and release each chunk after processing it.

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
from seclogx import Case, IngestOptions

# Create or open a case
c = Case.create("incident42")          # first time
# c = Case.open("incident42")          # use this instead in subsequent sessions

# Ingest (same semantics as the CLI; PATH or "PATH:HOST" strings)
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
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
    workers=8,
    options=IngestOptions(staging_format="auto"),
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
| Ingest resources | `IngestOptions(memory_limit="2GB", threads=2, staging_chunk_bytes=64 * 1024 * 1024, flatten_batch_bytes=256 * 1024 * 1024, staging_format="auto")` |
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
