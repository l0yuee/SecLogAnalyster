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
  task has no extension at all), so `ingest/logsources/sniff.py` peeks at file
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
- **Text/XML decoding tries UTF-8, UTF-16, then GB18030 (a superset of
  GBK/GB2312) before an always-succeeds Latin-1 fallback**
<<<<<<< HEAD
  (`textdecode.decode_text`, used by every aux parser including
  Scheduled Tasks XML, and by Sigma rule loading -- see below). This
  covers Simplified/Traditional Chinese-locale content and binary-ish
  data without crashing, but is still a best-effort guess, not real
  charset detection -- content in an encoding outside this list (e.g.
  Shift-JIS, Big5, KOI8-R) can still decode as readable-looking but wrong
  text rather than being flagged as misdecoded.
- **Every text file seclogx reads or writes itself -- Sigma rule YAML
  (bundled or `--rules`-supplied), `case.json`, the bundled ATT&CK/task
  baseline data, ingest log summaries, and `--out` CSV exports -- uses an
  explicit `UTF-8` encoding rather than the OS locale default.** Without
  this, a non-UTF-8-locale environment (notably GBK/cp936 on
  Chinese-locale Windows) would decode/encode using that locale's codec
  instead, and any content outside that codec's repertoire -- including
  plain UTF-8 punctuation like curly quotes or an em dash, present
  throughout the bundled Sigma rule set -- raised an uncaught
  `UnicodeDecodeError`/`UnicodeEncodeError` (this was the concrete crash
  previously hit running `hunt()` on such a machine, since rule loading
  is the first thing `hunt()` does). Console output (CLI stdout/stderr)
  is separately forced to UTF-8 with a replace-on-failure fallback at
  startup for the same reason.
=======
  (`ingest/logsources/sniff._decode_text`, used by every aux parser
  including Scheduled Tasks XML). This covers Simplified/Traditional
  Chinese-locale content and binary-ish data without crashing, but is
  still a best-effort guess, not real charset detection -- content in an
  encoding outside this list (e.g. Shift-JIS, Big5, KOI8-R) can still
  decode as readable-looking but wrong text rather than being flagged as
  misdecoded.
>>>>>>> d85ffe46e04a390724dab942e86787bf24fc8ea4
- **`Case.suspicious_tasks()`'s known-Microsoft-task baseline
  (`data/scheduled_tasks/known_microsoft_tasks.json`) is a curated,
  best-effort reference, not exhaustive or pinned to a specific Windows
  version/edition, and not a code-signing or hash check.** It only flags
  a *known* task path whose action executable falls outside that entry's
  expected location(s) -- an unlisted task path (including legitimate
  third-party or line-of-business tasks) is never compared, and a task
  matching a listed path/location pair is never verified against the
  actual binary's signature or hash.
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
  `ingest/logsources/parsers/weberror.py` matches. A customized error-log format, or raw
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

## Linux log ingestion (syslog / auth.log / auditd / systemd journal)

- **Format is detected by content, not filename or extension** -- same
  reasoning and same non-guarantee as the Windows non-EVTX families above
  (`AuxIngestReport.unknown_samples` / "files unrecognized", never silent).
- **`auth.log`/`secure` are not a separate sniff kind or table.** They're
  `syslog`-format lines like any other; `Case.auth_events()` /
  `seclogx auth` derives a curated SSH/sudo/PAM/account-management view
  from already-ingested `syslog` rows by recognizing program names and
  message shapes -- see the next two bullets for exactly what it
  recognizes.
- **`auth_events()`'s SSH recognition covers OpenSSH's standard log
  messages** (Accepted/Failed/Invalid user/disconnect variants) --
  non-OpenSSH SSH daemons, or a customized/localized OpenSSH build,
  produce messages this doesn't recognize (excluded from the result, not
  misparsed).
- **`auth_events()`'s session/account-management recognition covers
  shadow-utils (`useradd`/`userdel`/`usermod`/`groupadd`/`groupdel`/
  `passwd`) and generic `pam_unix(*:session)` open/close messages** --
  other PAM modules, or a system using something other than shadow-utils
  for account management, aren't recognized.
- **BSD/RFC-3164 syslog lines have no year in their timestamp.** It's
  inferred from the ingested file's mtime (`ingest/logsources/parsers/syslog.py`),
  a best-effort heuristic, not a guarantee -- a file whose mtime doesn't
  reflect when its content was actually written (e.g. copied during
  acquisition without preserving timestamps) can get the wrong year. RFC
  5424 lines carry a full timestamp and aren't affected.
- **`syslog.facility`/`severity` are NULL unless the line has a `<PRI>`
  prefix.** Most real-world `/var/log/syslog`/`auth.log` files use
  rsyslog's default file template, which omits it entirely -- this is a
  property of the log format actually present on disk, not a parsing gap.
- **RFC 5424 structured-data (`[SD-ID key="value" ...]`) parsing is
  best-effort**, via a straightforward bracket/key-value regex rather
  than a full RFC 5424 grammar -- doesn't handle every edge case of
  escaped characters inside SD-DATA values.
- **`auditd_logs.syscall` is the raw number reported, not resolved to a
  name.** The Linux syscall-number-to-name table is architecture-dependent
  (differs between x86_64, aarch64, etc.); resolving it generically
  wasn't worth the complexity for v1.
- **A real auditd event is often several related lines** (e.g. SYSCALL +
  EXECVE + CWD + PATH, all sharing one `audit_serial`) that aren't
  stitched back into a single row -- correlate them yourself with `WHERE
  audit_serial = ...`.
- **auditd's key=value tokenizer is generic, not format-aware per
  `type=`.** A record whose value contains nested `key=value`-shaped text
  inside a quoted field (some `USER_AUTH`/`USER_CMD` records embed a
  `msg='op=... res=...'` sub-message) can produce an imperfect split for
  that sub-message -- the record itself is still counted as parsed
  successfully (the header always parses), just with less precise field
  extraction for that one nested value.
- **`journal_logs` parses the journal *export* format**
  (`journalctl -o json`), not the binary journal itself
  (`/var/log/journal/**` or `/run/log/journal/**`), which isn't portable
  across systems and isn't ingested.
- **Crontab/`/etc/cron.d` definition files, `last`/`wtmp` binary login
  records, and package-manager logs (`dpkg.log`, `yum.log`, ...) are out
  of scope in v1** -- crontab files are a persistence-relevant config
  artifact (not a log) that could get Scheduled-Tasks-style treatment
  later; `wtmp`/`utmp` is an architecture-dependent binary struct with no
  portable parse; package-manager logs weren't judged high-value enough
  yet to prioritize. Same kind of deliberate v1 scope decision as
  Procmon/Autoruns/FREB above.
- **No Linux-specific Sigma logsource routes or detection rules ship in
  v1** -- ingestion and query access only (`syslog`/`auditd_logs`/
  `journal_logs` are fully queryable via `search()`/`query()`/`fields()`,
  and `auth_events()` covers the non-Sigma heuristic case), matching how
  Scheduled Tasks/web/Exchange logs also shipped without their own Sigma
  routes.

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

- **Single-machine by default; an opt-in, environment-variable-activated
  distributed mode exists** (`src/seclogx/distributed/`, see
  [10. Distributed deployment](guides/10_distributed_deployment.md)) --
  not on unless `SECLOGX_BROKER_URL`/`SECLOGX_STORAGE_BACKEND` are set,
  and default behavior is unchanged either way.
- **What's distributed: ingest (both pipelines' per-file parse tasks) and
  Sigma hunting (independent rules fanned out across workers).** What is
  *not*: query execution. There is no distributed SQL engine -- DuckDB
  still runs any single query or rule on exactly one process, against the
  shared Parquet lake. Distributed mode means more independent things can
  run concurrently (more ingest files parsed in parallel across machines,
  more hunt rules evaluated in parallel, more analysts querying the same
  lake at once); it does not make one query faster.
- **S3-backed storage (`SECLOGX_STORAGE_BACKEND=s3`) needs a broker
  (`SECLOGX_BROKER_URL`) configured too if more than one machine will run
  `seclogx ingest` against the same case concurrently** -- `case.json`'s
  locking falls back to a Redis-based lock once a broker is configured,
  which is what makes concurrent multi-machine writers to the same case
  safe; a plain local file lock (used when no broker is configured) isn't
  a reliable cross-machine coordination mechanism over a network
  filesystem.
- **`case.json`, `staging/`, and `logs/` are never moved to S3, in any
  mode.** Only `lake/` (the Parquet payload) is affected by
  `SECLOGX_STORAGE_BACKEND` -- case metadata and ingest-time scratch space
  stay on whatever local/NFS directory `--case-root` points at. This is a
  deliberate scope boundary, not a gap: they're small, coordinator-only
  bookkeeping, not what needs to scale.
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
- **Ingest is bounded-memory per file, not per pathologically large
  individual file.** Both pipelines now stage each file to NDJSON on disk
  and bulk-flatten via DuckDB reading straight off disk, so coordinator
  memory during ingest is bounded by (one file's parse footprint) x
  `--workers`, not by total batch size -- see "Why not Dask" in
  `docs/architecture.md` for the mechanism. What's *not* bounded: each
  worker still reads one whole file into memory to parse it (EVTX
  streams to NDJSON as it parses, but the non-EVTX parsers need the whole
  file for encoding detection first), so a single individual file large
  enough on its own to exceed available memory is still a per-file risk,
  independent of batch size or worker count.
<<<<<<< HEAD
- **Staged NDJSON (`staging/`, `staging_aux/`) is gzip-compressed and kept
  by default, trading some ingest CPU time for a much smaller on-disk
  case relative to an uncompressed-and-kept staging directory.** Without
  compression, a case directory could land at several times the source
  evidence's size -- rendered-as-JSON EVTX records alone run considerably
  larger than the source binary `.evtx`, and staging is additive on top
  of the already-compressed Parquet lake. This is a memory/disk/speed
  three-way tradeoff, not a solved problem: `--no-keep-staging` cuts disk
  further (at the cost of needing to re-ingest, not just re-flatten, to
  recover from a bad flatten), and gzip level 1 was chosen to bias toward
  ingest speed over maximum compression ratio. See "Performance and scale
  notes" in [08. Performance & scale](guides/08_performance_and_scale.md)
  for the full tradeoff and the companion fix (unrecognized files, e.g.
  PE/ELF binaries mixed into evidence, are never hashed or staged).
=======
>>>>>>> d85ffe46e04a390724dab942e86787bf24fc8ea4
