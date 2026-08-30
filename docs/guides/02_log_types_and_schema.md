# 2. Log types and schema

**Language: English | [中文](02_log_types_and_schema.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | 02. Log types & schema | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md)

---

This guide answers "what does each table hold, and what should I actually
look at first" for all six log families seclogx normalizes. For the exact
column-by-column reference (types, nullability, partition keys), see
`docs/schema.md`; for how each format is ingested, see `docs/architecture.md`.

## The normalized `events` schema

Every record from every channel, regardless of provider, is normalized
into the same set of columns -- see `docs/schema.md` for the full list.
The most important ones for day-to-day querying:

| Column | What it is |
|---|---|
| `time_created` | Event timestamp, UTC |
| `host` | The host label *you* assigned at ingest time |
| `computer` | The hostname embedded in the log itself (can differ from `host`) |
| `channel` | e.g. `Security`, `Microsoft-Windows-Sysmon/Operational` |
| `event_id` | Windows Event ID |
| `provider_name` | Event provider |
| `process_id` / `thread_id` | Generating process/thread |
| `user_sid` | Security context SID |
| `event_data` | Provider-specific fields as JSON (see below) |
| `source_file` / `source_path` / `file_sha256` | Provenance / chain of custody |

## The `event_data` field

Everything provider-specific (Sysmon's `Image`, `CommandLine`,
`ParentImage`; Security's `TargetUserName`, `LogonType`; etc.) lives in
one `event_data` JSON column, because the set of fields varies
enormously by provider and event type. Pull a field out with DuckDB's
`->>` operator:

```sql
SELECT (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
```

> **Always parenthesize `(event_data ->> 'Field')` whenever your `WHERE`
> clause combines it with another condition via `AND`/`OR`/`LIKE`.**
> DuckDB's `->`/`->>` operators don't bind as tightly as you'd expect
> against `LIKE`/`AND` in a compound expression -- an unparenthesized
> `event_data ->> 'Image' LIKE '%foo%' AND ...` can misparse and fail at
> execution time with a confusing type-cast error (`Could not convert
> string '{...}' to BOOL`), rather than a clear syntax error. Wrapping
> the extraction in parens, as in every example in this guide, avoids it
> entirely. A single, standalone `event_data ->> 'Field'` with no other
> `AND`/`OR` in the query is fine either way.

If you don't know the exact field name for something, `CaseDB.search()`
/ `seclogx query ... event_data::VARCHAR ILIKE '%...%'` does a full-text
search across it -- see [07. Recipes](07_recipes.md) -- or read on for
`seclogx fields`, which lists real field names directly from your data.

## The other tables: `web_logs`, `web_error_logs`, `scheduled_tasks`, `exchange_message_tracking`, `exchange_logs`

Windows Event Log isn't the only artifact `ingest` normalizes. Each of
these is fundamentally a different shape, so each gets its own table
rather than being crammed into `events` -- full column reference in
`docs/schema.md`. Every one of them is also reachable as a plain
`pandas.DataFrame` through a named `Case` accessor (`c.web_logs()`,
`c.scheduled_tasks()`, ...), the same first-class treatment `events` gets
via `summary()`/`hosts()`/`channels()` -- see [06. Python API](06_python_api.md).

| Table | What it holds | Key columns |
|---|---|---|
| `web_logs` | **Access logs**: IIS, nginx, Apache, and Tomcat HTTP access logs, unified | `log_type`, `client_ip`, `method`, `uri_stem`, `uri_query`, `status`, `user_agent`, `referer` |
| `web_error_logs` | **Error/diagnostic logs**: nginx, Apache, Tomcat, and IIS HTTP.sys (HTTPERR) -- the other major web-application log category, unified | `log_type`, `severity`, `client_ip`, `message`, plus IIS HTTPERR's `method`/`uri`/`status` |
| `scheduled_tasks` | On-disk Task Scheduler task definitions (`System32\Tasks\**`) -- a persistence artifact, distinct from the Task Scheduler *event log* (already in `events`) | `task_path`, `author`, `enabled`, `hidden`, `actions` (JSON), `triggers` (JSON) |
| `exchange_message_tracking` | Exchange mail flow (who sent what to whom) | `sender_address`, `recipient_address`, `message_subject`, `event_id` (Exchange's own, not a Windows Event ID) |
| `exchange_logs` | Every other Exchange CSV log type (HttpProxy, ActiveSync, EWS, ...), fields preserved verbatim | `log_type`, `fields` (JSON, query with `fields ->> 'field-name'`) |

A few things worth knowing before you query these:

- **Format is detected by content, not filename or extension** -- a live
  Task Scheduler task file has no extension at all, and forensic tools
  routinely rename exported logs. A file matching none of the supported
  formats is reported as unrecognized in the ingest summary, never
  silently skipped.
- **`web_logs` covers the access-log category; `web_error_logs` covers the
  error/diagnostic-log category** -- the two major log categories every
  web application produces. They're separate tables because they're
  structurally unrelated (access logs have a request/response shape;
  error logs are just severity + free text).
- **In `web_logs`, nginx vs. Apache vs. Tomcat is a best-effort label**,
  not a hard detection -- Common/Combined Log Format is byte-identical
  across all three; `log_type` falls back to `web_access` when no
  path/filename hint is available. IIS is always detected reliably
  (self-describing header).
- **In `web_error_logs`, the engine label *is* a real detection** -- each
  engine's error-log format is distinct and unambiguous, unlike access
  logs. Only each engine's default/standard format is recognized (a
  customized `log_format`/`ErrorLogFormat`, or raw unstructured stdout
  mixed into Tomcat's `catalina.out`, produces reported parse errors for
  those lines rather than a misparse).
- **Exchange support is scoped to Message Tracking as first-class
  columns**; every other Exchange log type (there are over a dozen)
  lands in `exchange_logs` with all fields preserved in `fields`, still
  fully queryable, just not promoted to real columns.
- See [07. Recipes](07_recipes.md) for recipes, and `docs/known_limitations.md`
  for the full list of scope decisions.

## Quick reference: analyzing each log type

Every table below is always reachable the fully generic way regardless of
whether it has a dedicated interface: `seclogx query <case> "<SQL>"` /
`seclogx table <case> <name>` on the CLI, and `Case.query()`/
`Case.db.table(name)` (plus their `_chunks` siblings) in Python -- or,
if you'd rather not write SQL at all, `seclogx search <case> <table>` /
`Case.search()` (plain field/value conditions: exact, fuzzy, or regex
matching -- see [03. Querying & search](03_querying_and_search.md)). The
columns below are the *additional*, purpose-built interfaces each table
gets on top of that.

| Log type | Table | Dedicated CLI | Dedicated Python (eager / chunked) | Sigma hunting |
|---|---|---|---|---|
| Windows Event Log | `events` | `summary`, `channels`, `timeline`, `hunt` | `summary()`/`channels()`/`hosts()`, `events()` / `events_chunks()`, `timeline()` / `timeline_chunks()` | Yes -- most bundled rule categories |
| Web access logs (IIS/nginx/Apache/Tomcat/Exchange-HttpProxy) | `web_logs` | none -- use `table web_logs` / `query` | `web_logs(log_type=)` / `web_logs_chunks(log_type=)` | Yes -- `category: webserver` (bring your own rules; none bundled by default) |
| Web error logs (nginx/Apache/Tomcat/IIS HTTPERR) | `web_error_logs` | none -- use `table web_error_logs` / `query` | `web_error_logs(log_type=)` / `web_error_logs_chunks(log_type=)` | No -- query directly |
| Scheduled Tasks | `scheduled_tasks` | `tasks [--suspicious]` | `scheduled_tasks()` / `scheduled_tasks_chunks()`, `suspicious_tasks()` (heuristic) | No -- use `suspicious_tasks()` / query directly |
| Exchange Message Tracking (mail flow) | `exchange_message_tracking` | none -- use `table exchange_message_tracking` / `query` | `exchange_message_tracking()` / `exchange_message_tracking_chunks()` | No -- query directly |
| Other Exchange logs (HttpProxy, EWS, EAS, ...) | `exchange_logs` | none -- use `table exchange_logs` / `query` | `exchange_logs(log_type=)` / `exchange_logs_chunks(log_type=)` | No -- query directly |

`seclogx sources <case>` isn't table-specific -- it's the one command to
run first, before any of the above: a row count per table so you know
what the case actually has before picking which of these to reach for.

What to actually look for in each, at a glance (full recipes in
[07. Recipes](07_recipes.md)):

- **`events`** -- the day-to-day DFIR core: process creation
  (parent/child chains, LOLBins), logon activity by type, PowerShell
  script blocks, registry/file changes. Start with `summary()`/
  `channels()` to see what actually got captured (was Sysmon running?),
  then `hunt()` for a first pass.
- **`web_logs`** -- anomalous status codes, uncommon URI extensions
  hit with a 200 (possible webshells), suspicious user agents, one
  client IP dominating traffic.
- **`web_error_logs`** -- error spikes correlated with `web_logs`
  anomalies at the same timestamp; IIS HTTPERR specifically catches
  requests HTTP.sys itself rejected *before* reaching an IIS worker
  process, so it can surface exploitation attempts that never show up
  in `web_logs` at all.
- **`scheduled_tasks`** -- persistence hunting: hidden or unauthored
  tasks, actions invoking a LOLBin, action paths under Temp/AppData/
  Public. `suspicious_tasks()` runs this heuristic for you.
- **`exchange_message_tracking`** -- phishing and mail-based
  exfiltration: sender/recipient/subject sweeps, unexpected external
  mail flow, a sender domain that doesn't match its claimed identity.
- **`exchange_logs`** -- Exchange HTTP-based compromise (e.g.
  ProxyShell-style attacks) where the relevant activity is in
  HttpProxy/OWA/ECP access patterns rather than mail flow -- sweep
  `fields` by content when you don't know the exact schema.

## Which fields can I search on?

Two questions come before writing any search: *what fields does this
table actually have*, and *which one is the right one for what I'm
trying to find*. `seclogx fields <case> <table>` / `Case.fields()`
answers the first directly from this case's real, ingested data (not a
static list -- a `web_logs` field list looks different depending on what
a site's IIS admin chose to log, and `event_data`'s keys are entirely
provider-specific, so no fixed list would be accurate for every case
anyway):

```bash
seclogx fields incident42 events
```
```
                    Fields in events (sampled)
  field          where              seen_in_sample  example
  channel        column             102451          Microsoft-Windows-Sysmon/Operational
  event_id       column             102451          1
  host           column             102451          WKS01
  ...
  Image          inside event_data  41200           C:\Windows\System32\cmd.exe
  CommandLine    inside event_data  41200           cmd.exe /c whoami
  TargetUserName inside event_data  8310            alice
  ...
```

Each row is a field name you can pass to `eq=`/`contains=`/`regex=`,
where it comes from (a real column, or a key found inside a JSON
catchall like `event_data`), how many of a sample of rows had it, and one
real example value -- so you can see the shape of the data (is
`CommandLine` quoted? is `status` a string or a number?) before writing a
condition against it. It's computed from a bounded sample (`--sample-size`,
default 5000 rows), never a full table scan, so it's safe to run against
a table of any size; a genuinely rare field can occasionally be missed if
it shows up in fewer than 1-in-`sample-size` rows.

```python
c.fields("events")     # -> Image, CommandLine, TargetUserName, ... (from event_data)
c.fields("web_logs")   # -> status, uri_stem, client_ip, ... (real columns)
```

For the second question -- which field actually gets you what you want --
a starting cheat sheet per log type (run `seclogx fields` on your own
case for the full, real list; provider/site-specific fields especially
vary):

| Table | Start with these fields |
|---|---|
| `events` (process creation, Sysmon EventID 1) | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes` |
| `events` (network connection, Sysmon EventID 3) | `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname` |
| `events` (file/registry, Sysmon EventID 11/13) | `Image`, `TargetFilename` / `TargetObject`, `Details` |
| `events` (PowerShell, EventID 4104) | `ScriptBlockText` |
| `events` (logon, Security EventID 4624/4625) | `TargetUserName`, `LogonType`, `IpAddress` |
| `events` (always available, any channel) | `channel`, `event_id`, `host`, `computer`, `time_created`, `user_sid` |
| `web_logs` | `uri_stem`, `uri_query`, `status`, `method`, `client_ip`, `user_agent`, `referer`, `log_type` |
| `web_error_logs` | `severity`, `message`, `client_ip`; IIS HTTPERR only: `method`, `uri`, `status` |
| `scheduled_tasks` | `author`, `hidden`, `enabled`, `actions`, `triggers`, `task_path`, `principal_user_id` |
| `exchange_message_tracking` | `sender_address`, `recipient_address`, `message_subject`, `recipient_status`, `event_id` |
| `exchange_logs` | `log_type` first (to see what kind of Exchange log you actually have), then `seclogx fields` for that log type's real field names |

For `events` specifically, note that which fields exist depends on the
*channel* -- `Image`/`CommandLine` are Sysmon fields and won't appear on
a Security-channel logon event, and vice versa for `TargetUserName`/
`LogonType`. `seclogx fields` samples across the whole table, so if you
want the fields for one specific channel, filter first (see
[07. Recipes](07_recipes.md), most of which start with `channel = '...'`).

Next: [03. Querying & search](03_querying_and_search.md) for how to
actually turn these field names into a query, with or without SQL.
