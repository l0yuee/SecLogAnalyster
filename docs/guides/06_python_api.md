# 6. Python / notebook API

**Language: English | [中文](06_python_api.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | 06. Python API | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

Everything the CLI does is available as a plain Python API, returning
`pandas.DataFrame` objects throughout -- built for dropping straight
into a Jupyter notebook alongside your usual pandas analysis. For the
bounded-memory (`_chunks`) and `search()` memory-safety mechanics used
below, see [03. Querying & search](03_querying_and_search.md).

```python
from seclogx import Case

# Create or open a case
c = Case.create("incident42")          # first time
c = Case.open("incident42")            # subsequent sessions

# Ingest (same semantics as the CLI; PATH or "PATH:HOST" strings)
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
)
print(report.summary_text())
report.to_dataframe()                  # per-file staging detail as a DataFrame (EVTX pass)
report.aux.to_dataframe()              # same, for the Scheduled Tasks/IIS/web/Exchange pass

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
# fields() answers both from this case's real data -- one row per field
# (real column or a key found inside a JSON catchall like event_data),
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
| Lifecycle | `Case.create(name, case_root=)`, `Case.open(name, case_root=)`, `Case.list_cases(case_root=)`, `c.info()` |
| Ingest | `c.ingest(sources, workers=, keep_raw=, keep_staging=)` -> `IngestReport` |
| Exploration | `c.summary()`, `c.channels()`, `c.hosts()`, `c.table_counts()` |
| Fields / no-SQL search | `c.fields(table, sample_size=)`, `c.search(table, eq=, contains=, regex=, match=, case_sensitive=)`, `c.search_chunks(...)`, `c.search_to_csv(table, path, ...)` |
| Raw SQL | `c.query(sql)`, `c.query_chunks(sql, chunksize=)`, `c.db.table(name)`, `c.db.table_chunks(name, chunksize=)` |
| Per-log-family accessors | `c.events()` / `c.events_chunks()`, `c.web_logs(log_type=)` / `_chunks`, `c.web_error_logs(log_type=)` / `_chunks`, `c.scheduled_tasks()` / `_chunks`, `c.exchange_message_tracking()` / `_chunks`, `c.exchange_logs(log_type=)` / `_chunks`, `c.syslog()` / `_chunks`, `c.auditd_logs()` / `_chunks`, `c.journal_logs()` / `_chunks`, `c.db_logs(log_type=)` / `_chunks` |
| Scheduled Task triage | `c.suspicious_tasks()` |
| Auth event triage (over `syslog`) | `c.auth_events()` |
| Detection | `c.hunt(rules_dir=, min_level=)` -> `HuntResults` |
| Timeline | `c.timeline(start=, end=, host=, channel=, event_id=)` / `c.timeline_chunks(...)` |
| `CaseDB` (`c.db`) | `.tables`, `.table(name)` / `.table_chunks(name)`, `.sql(query)` / `.sql_chunks(query)`, `.by_event_id(ids)`, `.by_host(host)`, `.search(text)`, `.estimate(query)` -> `ResultSizeEstimate` |

## Distributed mode from Python

There's no separate API for this -- `Case.open()`/`Case.create()`/
`Case.ingest()`/`Case.hunt()` all resolve `seclogx.distributed.config.
ClusterConfig` from the environment automatically each time they run.
Set the same `SECLOGX_BROKER_URL`/`SECLOGX_STORAGE_BACKEND`/`SECLOGX_S3_*`
variables described in
[10. Distributed deployment](10_distributed_deployment.md) before
constructing/using a `Case`, and ingest/hunt dispatch through the
configured job queue and storage backend exactly like the CLI does -- no
code changes needed. Pass an explicit `cluster_config=` to override
per-call instead of relying on the environment, if you're driving several
differently-configured cases from one process.

Next: [07. Recipes](07_recipes.md) for worked, copy-pasteable examples
using this API (and its `seclogx search` no-SQL equivalents).
