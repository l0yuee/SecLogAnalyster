# Known limitations (v1)

These are deliberate v1 scope decisions or empirically-discovered edge cases,
not oversights -- documented so they're easy to revisit later.

## Ingestion / schema

- **`UserData`-based providers are stored but not field-flattened.** Many
  providers (RDP `TerminalServices-RemoteConnectionManager`, some Task
  Scheduler and Defender events) use `UserData` instead of `EventData`.
  Unlike `EventData`, `UserData`'s fields sit nested one level under a
  provider-specific root element name (e.g. `{"ServiceShutdown": {...}}`),
  which isn't flattened to a uniform Name->Value shape in v1. The raw blob
  is still stored in `event_data` and is fully covered by
  `CaseDB.search()` (full-text ILIKE), but per-field Sigma mapping
  (`detect/pipeline.py`) currently only targets `EventData`-style fields.
- **A small number of records can have a NULL `channel`.** Observed
  empirically (3 out of ~102k records across real sample data) on
  malformed/edge-case source records where the `Channel` element itself
  is absent. Handled gracefully (no crash, included in query results) but
  not root-caused further since it's a data-quality property of the
  source file, not a parser bug.
- **`--keep-raw` builds an in-memory index of a file's raw XML** (keyed by
  record id) before merging it into the NDJSON output, to stay correct
  even if the XML and JSON parses of the same file diverge on a corrupt
  chunk. This trades peak memory for correctness during staging of that
  file -- acceptable given `--keep-raw` is an explicit opt-in for
  evidentiary completeness on a specific case, not the default path.
- **A corrupted chunk aborts the rest of a file's parse.** Empirically,
  `PyEvtxParser.records_json()` raises at the generator level on a bad
  chunk rather than yielding a per-record error object, so a corrupted
  chunk partway through a file means the rest of that file is lost even
  if later chunks would have parsed fine. Staging records this as a
  `partial` status with the exact recovered-record count -- never
  silently reported as a clean success.
- **Keywords are stored as a raw hex string, not decoded.** Keyword bitmask
  meaning is provider-specific; decoding it generically wasn't worth the
  complexity for v1.
- **Sysinternals tools other than Sysmon are out of scope.** Sysmon writes
  to a normal `.evtx` channel and is fully covered. Procmon (`.PML`,
  proprietary binary format) and Autoruns (CSV/XML export) are not
  ingested in v1.

## Detection (Sigma / DuckDB backend)

- **Logsource categories route to Sysmon fields, not native Security
  equivalents.** E.g. `process_creation` maps to Sysmon EventID 1, not
  Security EventID 4688 -- deliberate, since most Sigma rules for these
  categories are written against Sysmon's field set (`Image`,
  `CommandLine`, `ParentImage`, ...) which mostly doesn't exist on native
  Security events by default. See `detect/pipeline.py` `LOGSOURCE_ROUTES`.
- **`DuckDBBackend` field expressions are parenthesized deliberately.**
  Empirically, DuckDB's `->`/`->>` JSON operators do not bind as tightly
  as expected against `LIKE ... AND ...` in a compound WHERE clause --
  an unparenthesized `event_data ->> 'Image' LIKE '...' AND ...`
  expression can misparse and fail at execution time with a confusing
  type-cast error, rather than a syntax error. Every field mapping in
  `detect/pipeline.py` wraps its expression in parens
  (`"(event_data ->> 'Image')"`) to guarantee correct grouping regardless
  of operator precedence. If you add new field mappings, keep this
  pattern.
- **Case-sensitive matching (`|cased`) and numeric comparison modifiers
  (`|lt`, `|gt`, ...) are not supported.** Rules using them fail
  conversion explicitly (reported by `seclogx rules validate` / a hunt's
  failure list) rather than silently producing an incorrect query.
- **Sigma correlation rules are not supported.**
- **The bundled ATT&CK lookup (`data/attack/techniques.json`) is a small,
  hand-curated table** covering only the techniques referenced by the
  bundled Sigma rules -- not the full ATT&CK framework, and not fetched
  live. It needs manual updates if the bundled rule set changes.

## Non-EVTX log ingestion (Scheduled Tasks / IIS / web access & error / Exchange)

- **Format is detected by content, not filename or extension.** Forensic
  acquisitions routinely rename or relocate files (a live Task Scheduler
  task has no extension at all), so `logsources/sniff.py` peeks at file
  content. This is a heuristic classifier, not a guarantee -- an
  unusually-truncated or nonstandard log header can be misclassified as
  `unknown` and reported as unrecognized rather than ingested (see
  `AuxIngestReport.unknown_samples` / the ingest summary's "files
  unrecognized" count -- never silent).
- **Legacy `.job` Scheduled Tasks (pre-Vista binary format) are not
  parsed.** Only the modern Task Scheduler 2.0 XML format
  (`C:\Windows\System32\Tasks\**`) is supported.
- **A task XML file containing a `<!DOCTYPE` declaration is rejected
  outright** (reported as a failed file, not silently skipped) as a
  defense-in-depth XXE guard, rather than attempting to sanitize or
  safely parse it -- legitimate Task Scheduler exports never contain one.
- **nginx vs. Apache vs. Tomcat cannot be reliably told apart from the log
  line alone.** Common/Combined Log Format is byte-identical across all
  three servers' default configurations; `log_type` for these is a
  path/filename heuristic (`sniff.guess_web_log_type`), falling back to
  the generic label `web_access` when no hint is available. IIS is
  detected reliably (its `#Software:`/`#Fields:` header is
  self-describing).
- **Only Common/Combined Log Format is supported for nginx/Apache/Tomcat.**
  A custom `log_format` (nginx) or `LogFormat` (Apache) directive
  producing a different field order/set will not match and those lines
  are counted as parse errors for that file (reported, not silently
  dropped) rather than misparsed.
- **Exchange support is scoped to Message Tracking (first-class columns)
  plus a generic catchall for every other Exchange CSV log type**
  (HttpProxy, ActiveSync/Eas, Ews, Imap, Pop, RpcHttp, ...). Exchange
  ships over a dozen such self-describing log formats; rather than
  hand-modeling each, non-message-tracking logs land in `exchange_logs`
  with every field preserved verbatim in `fields` (still fully queryable,
  just not promoted to first-class columns).
- **`recipient_address` in `exchange_message_tracking` is stored raw**,
  which can be a `;`-separated list for a single message sent to multiple
  recipients in one transport hop -- not split into multiple rows.
- **IIS's `extra` JSON catchall only fires for fields beyond the fixed
  set `iis.py` maps to real columns** -- if a site logs a custom W3C
  field, it lands there rather than as a first-class column, same
  principle as `event_data` for EVTX.
- **A source directory with no `.evtx` files is not an error** as long as
  it has at least one supported non-EVTX artifact (or vice versa) --
  `Case.ingest()` only raises `NoSourcesFoundError` if *both* passes find
  nothing.
- **Web-application error/diagnostic logs (`web_error_logs`) only
  recognize each engine's default log format.** nginx's default `error_log`
  format, Apache's traditional and 2.4+ `ErrorLogFormat`, Tomcat's default
  `java.util.logging` `SimpleFormatter` output (`catalina.<date>.log` /
  `localhost.<date>.log`), and IIS's documented HTTPERR field set are what
  `logsources/weberror.py` matches. A customized error-log format, or raw
  unstructured stdout mixed into `catalina.out` (common in practice,
  since Tomcat redirects raw `System.out`/`System.err` there too),
  produces parse errors for those lines (reported, not silently dropped)
  rather than a misparse.
- **A Tomcat log entry's attached stack trace is capped at 200 continuation
  lines** (`weberror._TOMCAT_MAX_CONTINUATION_LINES`) to bound memory on a
  pathological case; lines beyond the cap are counted as parse errors for
  that file rather than silently appended or dropped.
- **Unlike access logs, nginx/Apache/Tomcat error-log format is
  engine-specific and unambiguous** -- `log_type` in `web_error_logs` is a
  real detection (a distinct regex per engine in `sniff.py`), not the
  path/filename heuristic access logs need.
- **FREB (Failed Request Event Buffering), IIS's XML-based per-request
  diagnostic trace, and Apache's `mod_rewrite`/SSL request logs are out of
  scope in v1** -- only the standard access (W3C/CLF/Combined) and error
  (HTTPERR / `error_log` / catalina) log categories are covered.

## Plain-language search (`search.py` / `seclogx search` / `Case.search()`)

- **`seclogx fields` / `Case.fields()` / `discover_fields()` is
  sample-based (`LIMIT sample_size`, default 5000 rows), not an
  exhaustive scan.** A genuinely rare field/JSON key present in fewer
  than roughly 1-in-`sample_size` rows can be missed. Increase
  `--sample-size`/`sample_size` if you suspect this, or just try the
  field with `search()` directly -- an unknown key inside a table that
  has a JSON catchall returns zero matches rather than an error either
  way (see below), so there's no harm in trying a field `fields` didn't
  surface.
- **`equals` always compares the text representation of a value**, not
  its native type -- deliberate, so an analyst doesn't need to know or
  care whether `status` is stored as an integer: `eq={"status": "404"}`
  and a hypothetical `eq={"status": 404}` behave the same either way.
- **`contains` is a literal substring search, not a wildcard pattern.**
  The value's `%`, `_`, and `\` are escaped before being wrapped in
  `%...%`, so searching for a literal `%` or `_` works as expected rather
  than being interpreted as a SQL wildcard. Use `regex` if you actually
  need wildcard-like or more complex pattern matching.
- **`regex` uses DuckDB's RE2-based regex engine** -- no
  lookahead/lookbehind (RE2 doesn't support them), which most Sigma/log
  regex patterns don't need anyway.
- **Multiple values for one field (`--eq status=404,500` on the CLI, or
  `eq={"status": ["404", "500"]}` in Python) combine with OR; comma-splits
  in the CLI only apply to `--eq`/`--contains`, not `--regex`** (a regex
  pattern can legitimately contain a literal comma, so `--regex` treats
  its value as one whole pattern, never split).
- **A field that resolves into a JSON *array* column
  (`scheduled_tasks.actions`/`triggers`) can't be searched by key** --
  only JSON *object* columns support keyed extraction. Search `actions`/
  `triggers` directly (as a whole-column `contains`/`regex` match against
  its JSON-serialized text) instead of trying to reach a field inside one
  of its list entries.
- **An unresolvable field name only raises `UnknownFieldError` when the
  table has no JSON-object catchall to fall back to** (e.g.
  `scheduled_tasks`). On a table that does have one (`events`,
  `web_logs`, ...), an unknown key is indistinguishable from "a real key
  that just isn't present in this data" -- both correctly return zero
  matches rather than an error, since DuckDB's `->>` on a missing JSON key
  returns NULL rather than failing.
- **The memory-safety check (`search()`, refusing via `ResultTooLargeError`)
  is an estimate, not exact** -- `count(*)` for the row count (exact) times
  a bytes-per-row figure from a small sample (`LIMIT 2000` by default),
  extrapolated to the full result. A result with unusually wide variance
  in row size (e.g. `event_data`/`extra`/`fields` payloads that vary
  enormously in size row-to-row) can be estimated somewhat off in either
  direction. The default safety margin (`safety_fraction=0.25`, i.e. an
  eager fetch is allowed up to a quarter of currently available memory)
  is deliberately conservative to absorb this.
- **"Available system memory" is best-effort and can be unknown.**
  `memcheck.available_memory_bytes()` tries `/proc/meminfo` (Linux),
  `os.sysconf` (POSIX, coarser), then `GlobalMemoryStatusEx` (Windows);
  on a platform/environment where none of those work, it returns `None`,
  and `fits_in_memory()` falls back to a fixed 200MB absolute cap rather
  than assuming unlimited memory.

## Scale

- Designed for a single workstation, not a distributed system -- see
  `docs/architecture.md` for the scale-out extension point if that's ever
  needed.
- **`.sql()`/`.table()` (and the `Case` accessors built on them --
  `web_logs()`, `events()`, `timeline()`, etc.) materialize the entire
  result as one pandas DataFrame.** DuckDB's query execution underneath is
  lazy/out-of-core, but that doesn't help once the last step calls
  `fetchdf()` -- fine for a filtered/aggregated result, but web access/
  error logs especially can realistically reach terabyte scale across a
  case, well past what fits in memory as one DataFrame. Every such
  accessor has a `_chunks` sibling (`sql_chunks()`/`table_chunks()`,
  `query_chunks()`, `web_logs_chunks()`, `timeline_chunks()`, ...)
  returning an `Iterator[pd.DataFrame]` instead, with memory bounded by
  `chunksize` rather than total result size -- use these for any table or
  query not already known to be small. The CLI (`query`/`table`/`tasks`/
  `timeline`) uses the chunked path automatically for both `--out` and
  the console preview.
- **Ingest does not yet have the same bounded-memory property for the
  non-EVTX log families.** The EVTX pipeline streams to disk per file and
  bulk-flattens via DuckDB's own streaming `read_ndjson()`, so it never
  holds more than one file's records as a Python list at a time. The
  Scheduled Tasks/IIS/web/Exchange pipeline (`logsources/ingest.py`)
  parses each file to a Python `list[dict]` and accumulates every file's
  rows per table in memory across the whole ingest batch before writing
  Parquet -- fine at the volumes exercised so far, but a single ingest run
  processing enough log files to reach terabyte scale *in one batch*
  would need the same stage-to-disk-then-bulk-flatten treatment the EVTX
  pipeline already has. Not yet implemented; this is specifically an
  ingest-time boundary, separate from (and not fixed by) the query-side
  chunking above.
