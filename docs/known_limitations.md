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

## Non-EVTX log ingestion (Scheduled Tasks / IIS / web access / Exchange)

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

## Scale

- Designed and tested for realistic single-case volumes (**<100GB**) on a
  single workstation, per the intended use case. DuckDB + Parquet handle
  this comfortably with lazy/out-of-core execution, but this is not a
  distributed system -- see `docs/architecture.md` for the scale-out
  extension point if that's ever needed.
