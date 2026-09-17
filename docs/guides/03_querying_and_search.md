# 3. Querying and search

**Language: English | [中文](03_querying_and_search.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | 03. Querying & search | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

Every table (see [02. Log types & schema](02_log_types_and_schema.md)) is
reachable three ways: raw SQL, the no-SQL `search()` interface, or a
generic full-table/full-query fetch. All three have a bounded-memory
variant. This guide covers all of it -- what interface to reach for, and
how the memory-safety mechanics work underneath.

## Raw SQL

`seclogx query <case> "<SQL>"` / `Case.query()` run arbitrary SQL against
any table in the case:

```sql
SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
ORDER BY time_created
```

`Case.db.table(name)` / `seclogx table <case> <name>` fetch a table's full
contents with no `WHERE` clause needed. See
[05. CLI reference](05_cli_reference.md) and
[06. Python API](06_python_api.md) for the full option/method list.

## Searching without SQL

For field-based filtering without SQL, use `seclogx search <case> <table>`
on the CLI or `Case.search()` in Python. Aggregation, joins and arbitrary
expressions still use SQL. Search conditions are plain field/value pairs,
one of three kinds:

| Condition | Meaning | CLI flag | Python |
|---|---|---|---|
| Exact match | field equals a value exactly | `--eq FIELD=VALUE` | `eq={"field": "value"}` |
| Fuzzy match | field contains a value as a substring | `--contains FIELD=VALUE` | `contains={"field": "value"}` |
| Regular expression | field matches a regex pattern | `--regex FIELD=PATTERN` | `regex={"field": "pattern"}` |

```bash
# Find webshell-like hits: uri_stem contains "shell", status exactly 200
seclogx search incident42 web_logs --contains uri_stem=shell --eq status=200
```
```python
from seclogx import Case
c = Case.open("incident42")
c.search("web_logs", contains={"uri_stem": "shell"}, eq={"status": 200})
```

A few things that make this more than "LIKE with extra steps":

- **Matching is case-insensitive by default** (`--case-sensitive` / 
  `case_sensitive=True` to opt into exact-case matching).
- **Multiple values on one condition combine with OR**: `--eq
  status=404,500` (CLI, comma-separated) or `eq={"status": ["404",
  "500"]}` (Python) matches either value.
- **Multiple different conditions combine with AND by default** (every
  condition must match), or OR with `--match-any` / `match="any"` (any
  one condition matching is enough).
- **Field names work whether or not they're a "real" column.** A field
  that isn't one of the table's own columns (`status`, `uri_stem`, ...) is
  looked up as a key inside the table's provider-specific JSON catchall
  (`event_data` for `events`, `extra` for `web_logs`/`web_error_logs`,
  `fields` for `exchange_logs`) automatically -- `Image`, `CommandLine`,
  `TargetUserName`, whatever the underlying provider actually calls it,
  just works:

  ```bash
  seclogx search incident42 events --contains Image=mimikatz --eq channel="Microsoft-Windows-Sysmon/Operational"
  seclogx search incident42 events --regex CommandLine=".*-enc.*"
  ```

  A field name that isn't a real column *and* doesn't resolve inside any
  JSON catchall (most fields on `scheduled_tasks`, which has none) is
  reported clearly, listing the table's actual columns, rather than a
  cryptic database error. Not sure what fields a table has? See
  "Which fields can I search on?" in
  [02. Log types & schema](02_log_types_and_schema.md).
- **`--regex` uses regular expressions** (DuckDB's RE2-based engine --
  the same syntax most log-analysis tools use, no
  lookahead/lookbehind support, which log patterns rarely need anyway).
  `--contains` is always a literal substring, never a wildcard pattern --
  reach for `--regex` if you need real pattern matching.
- **`search()` checks estimated result size before fetching.** It refuses
  an estimated oversized DataFrame and points to the alternatives below.
  Sampling and changing available memory make this a guard, not a hard
  memory guarantee. See "The memory-safety check" below.

## Bounded-memory access for large tables

Table/query accessors such as `.query()`, `.table()`,
`.web_logs()` and `.timeline()` have `_chunks` siblings that
returns an `Iterator[pd.DataFrame]` instead of one DataFrame. This
matters because `.query()`/`.table()`/etc. call DuckDB's `.fetchdf()`
under the hood, which materializes the *entire* result as one DataFrame:
fine for a filtered or aggregated result, but web access/error logs
especially can realistically reach terabyte scale across a case, well
past what fits in memory as one DataFrame -- DuckDB's lazy, out-of-core
*query execution* doesn't help once the last step pulls everything into
one object. The `_chunks` accessors use DuckDB's chunked fetch instead,
so Python receives approximately `chunksize` rows at a time (default
100,000, rounded to DuckDB vectors of 2,048 rows).

This controls result delivery, not total query RSS. Wide rows still need
more memory; DuckDB sorts, joins and aggregations have their own working
state. Release each chunk after processing it: `list(iterator)` or a final
`pd.concat()` recreates a full-result allocation. `IngestOptions` applies
to ingest conversions and does not set limits on these query connections
or pandas. Sigma hunts and derived heuristic results also have separate
memory behavior; they do not all offer chunked variants.

```python
from seclogx import Case
c = Case.open("incident42")

# Instead of this on a huge table (materializes everything at once):
# df = c.web_logs(log_type="nginx")

# ...iterate bounded-size chunks:
for chunk in c.web_logs_chunks(log_type="nginx"):
    # chunk is a normal pandas.DataFrame, just not the whole result
    suspicious = chunk[chunk["status"] >= 400]
    if not suspicious.empty:
        suspicious.to_csv("web_errors.csv", mode="a", header=False, index=False)

# Same pattern for any raw SQL, any table, and the timeline:
for chunk in c.query_chunks("SELECT * FROM web_error_logs WHERE severity IN ('error', 'SEVERE')"):
    ...
for chunk in c.db.table_chunks("exchange_message_tracking"):
    ...
for chunk in c.timeline_chunks(host="WKS01"):
    ...

# Tune chunksize (rows per chunk) if the default doesn't fit your row width:
for chunk in c.web_logs_chunks(chunksize=20_000):
    ...
```

Every `_chunks` accessor mirrors its eager counterpart's signature (same
filters, same `log_type=`/`host=`/etc. keywords) plus a `chunksize`
keyword. Named table accessors yield nothing when that table is absent,
matching their eager empty-DataFrame behavior. Arbitrary `query_chunks()`
SQL still raises for nonexistent tables or an empty case.

The CLI applies this automatically: `seclogx query`/`table`/`tasks`/
`timeline` stream chunks straight to CSV for `--out`, and the console
preview only pulls enough rows to fill the table (never the whole
result) -- see [05. CLI reference](05_cli_reference.md). You don't need
`--chunks` or any equivalent flag; it's just how those commands work.

## The memory-safety check

`.search()` goes one step further than the `_chunks` pattern above: it
estimates the result size *before* fetching (an exact `count(*)` times a
bytes-per-row figure from a small sample) and compares it against the
machine's actual currently-available memory. If materializing the whole
result as one DataFrame is estimated to use more than a quarter of that,
it refuses with `ResultTooLargeError`. Row-size variance can make the
estimate inaccurate, and the count/sample queries themselves still need
execution resources:

```python
from seclogx.errors import ResultTooLargeError

try:
    df = c.search("web_logs", contains={"uri_stem": "shell"})
except ResultTooLargeError as e:
    print(e)
    # The message includes the estimate and names chunked alternatives.

# The two alternatives deliver results one chunk at a time:
for chunk in c.search_chunks("web_logs", contains={"uri_stem": "shell"}):
    ...                                                          # iterate
c.search_to_csv("web_logs", "hits.csv", contains={"uri_stem": "shell"})  # or stream to a file
```

`query()`/`table()`/etc. don't do this estimate-and-refuse check
themselves (only `.search()` does) -- for those, reach for the `_chunks`
sibling yourself whenever you're not sure a result is small. If you
already know a `.search()` result will be small (a tightly-scoped
condition, say), you don't need to do anything differently -- the check
only ever blocks a fetch that's actually estimated too large; anything
that fits returns a normal DataFrame exactly like the eager accessors
above.

The CLI does not request one eager result DataFrame: `seclogx search`
shows a bounded preview and tells you the estimated row/size count, and
`--out` streams matching rows to CSV. Query execution, disk and I/O
errors can still occur.

The lake has no atomic ingest snapshot: queries during an import can see
only some completed groups, and a failed import can leave earlier output.
Query after a successful ingest when complete-batch visibility matters;
re-importing the same source can append duplicates.

How the estimate itself works, and its caveats (sampling variance,
best-effort available-memory detection), are covered in
[08. Performance & scale](08_performance_and_scale.md).

`Case` supports the context manager protocol to close its DuckDB
connection cleanly:

```python
with Case.open("incident42") as c:
    df = c.summary()
```

Next: [04. Threat hunting](04_threat_hunting.md) for Sigma-rule-based
detection on top of these same tables.
