# Known limitations (v1)

These are current scope boundaries and known edge cases, documented so
analysts can distinguish supported behavior from remaining gaps.

## Ingestion / schema

- **Discovery is not a complete evidence inventory.** The scan filters
  empty auxiliary files and configured non-log suffixes before content
  classification. Inaccessible entries/directories can be skipped when
  `stat` or directory enumeration raises `OSError`; those omissions do
  not each receive a failed-file manifest entry. The `unknown` count
  covers files actually submitted to classification, not every path
  present under a source root.

- **Non-EVTX timestamp columns normalize explicit ISO offsets to UTC.**
  A timestamp ending in `Z`/`z`, `+08:00`, or `-0330` is stored as a UTC
  `TIMESTAMP` without a timezone marker, preserving microseconds. A source
  timestamp without an offset retains its wall-clock value; no timezone
  is guessed. Invalid timestamps become NULL. The result does not depend
  on staging shard boundaries or the DuckDB session timezone, and plain
  text fields that happen to resemble timestamps retain their original text.
  Existing Parquet files are not rewritten by this change; it applies to
  new imports. Re-importing into an existing case can append duplicate rows.
- **`UserData`-based providers are stored but not field-flattened.** Many
  providers (RDP `TerminalServices-RemoteConnectionManager`, some Task
  Scheduler and Defender events) use `UserData` instead of `EventData`.
  Unlike `EventData`, `UserData`'s fields sit nested one level under a
  provider-specific root element name (e.g. `{"ServiceShutdown": {...}}`),
  which isn't flattened to a uniform Name->Value shape in v1. The raw blob
  is still stored in `event_data` and is fully covered by
  `CaseDB.search()` (full-text ILIKE), but per-field Sigma mapping
  (`detect/pipeline.py`) currently only targets `EventData`-style fields.
- **Records can have a NULL `channel`.** Source records with no
  `Channel` element remain in query results with NULL in that column.
- **`--keep-raw` uses a temporary SQLite index of raw XML**, keyed by
  record ID and queried during the JSON pass. It no longer retains all
  XML in a Python dictionary, but still adds a parse, index I/O and
  temporary disk space. XML capture is best effort on corrupt chunks;
  the JSON recovery pass remains authoritative and some raw XML can be
  absent. Use it when XML fidelity is needed, not as a free option.
- **A corrupted chunk can abort the rest of an EVTX file's parse.**
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
  Security events by default. PowerShell's `ps_script`/`ps_module` are
  separate routes to its Operational channel (4104/4103), not Sysmon.
  See `detect/pipeline.py` `LOGSOURCE_ROUTES`.
- **`DuckDBBackend` field expressions are parenthesized deliberately.**
  DuckDB's `->`/`->>` JSON operators do not bind as tightly
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
- **Hunt results are collected in memory.** Each rule uses `fetchdf()`;
  matching frames are retained and concatenated. There is no chunked
  hunt API or `search()` size guard, and distributed workers return
  these frames to the coordinator. `IngestOptions` does not configure
  query/hunt connections or cap pandas memory.
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
  unrecognized" count). Discovery exclusions described above happen
  before this classification/reporting step.
- **Legacy `.job` Scheduled Tasks (pre-Vista binary format) are not
  parsed.** Only the modern Task Scheduler 2.0 XML format
  (`C:\Windows\System32\Tasks\**`) is supported.
- **A task XML file containing a `<!DOCTYPE` declaration is rejected
  outright** (reported as a failed file, not silently skipped) as a
  defense-in-depth XXE guard, rather than attempting to sanitize or
  safely parse it -- legitimate Task Scheduler exports never contain one.
- **Text/XML decoding tries UTF-8, UTF-16, then GB18030 (a superset of
  GBK/GB2312) before an always-succeeds Latin-1 fallback**
  (`textdecode.decode_text` for small documents and
  `textdecode.iter_text_lines` for streaming logs; QCloud only considers
  UTF-16 when a BOM is present). This
  covers many Chinese-locale inputs and binary-ish
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
  pathological case. Exceeding the limit raises `TextRecordTooLargeError`;
  the oversized current entry is not emitted with a truncated stack trace.
  Completed earlier entries can be retained with a `partial` file status.
- **Unlike access logs, nginx/Apache/Tomcat error-log format is
  engine-specific and unambiguous** -- `log_type` in `web_error_logs` is a
  real detection (a distinct regex per engine in `sniff.py`), not the
  path/filename heuristic access logs need.
- **FREB (Failed Request Event Buffering), IIS's XML-based per-request
  diagnostic trace, and Apache's `mod_rewrite`/SSL request logs are out of
  scope in v1** -- only the standard access (W3C/CLF/Combined) and error
  (HTTPERR / `error_log` / catalina) log categories are covered.

## Database log ingestion (MySQL/MariaDB / PostgreSQL / MSSQL / Oracle)

- **PostgreSQL parsing covers the common `%m [%p] %q%u@%d ` `log_line_prefix`
  shape only, not arbitrary custom prefixes.** `log_line_prefix` is a
  server-configurable setting; a Postgres instance configured with a
  substantially different prefix format won't be recognized as
  `postgresql` and its lines will be reported as parse errors, the same
  "best-effort, not exhaustive" honesty standard as `guess_web_log_type`.
- **MySQL general query log and slow query log classification depends on
  a marker/header line being present in the ingested file** (the literal
  `Time  Id  Command  Argument` header for general logs; a `# Time:`/`#
  Query_time:` comment line for slow logs) **appearing before any other
  non-comment content** -- only the *first* non-blank, non-comment line
  peeked is checked (same single-first-line heuristic every other
  content-sniffed format in this project uses). A slow-log file whose
  captured content leads with mysqld's plain-text startup banner rather
  than a query block may not be classified; a general log missing its
  header (e.g. mid-file forensic extraction) likewise.
- **Oracle alert log classification requires a timestamp-only line
  (`YYYY-MM-DDTHH:MM:SS.ffffff+TZ:TZ` on its own line) within the first
  16KB peeked.** A very long startup banner preceding the first timestamp
  entry could defeat this, same class of limitation as the MySQL
  marker-line dependence above.
- **MySQL error log's `[MY-XXXXX]` error code and `[Subsystem]` tag are
  only extracted for the 5.7+/8.0 bracketed format**; the older
  `YYMMDD HH:MM:SS [Level] message` format has no equivalent fields
  (`error_code`/`component`/`thread_id` are NULL for those rows).
- **`db_logs.error_code` is populated two different ways depending on
  `log_type`**: taken directly from a `[MY-XXXXX]` bracket for
  mysql_error, but regex-extracted (`ORA-\d{5}`) from anywhere in the
  accumulated message text for oracle -- not a parsed structured field
  for Oracle, just the first matching substring.
- **MSSQL `ERRORLOG` format is stable across recent versions but not
  guaranteed identical across every edition/version** -- the parser
  expects `<date> <time>.<cc>  <component>      <message>`; a
  significantly different layout (e.g. a heavily customized trace flag
  configuration) may not match.

## Tencent Cloud Host Security client log ingestion

- **Only local plaintext client logs are parsed.** This includes YDService,
  HIDS/YDLive, vulnerability and baseline scanner, YDFlame/YDUtils/
  YDQuaraV2, and YDEyes text formats. Private-cloud upload protocol payloads,
  protobuf/FlatBuffers/BLOB messages, and encrypted or compressed
  `result_file` contents are not decoded.
- **Several line envelopes are generic enough to need product context.** The
  Go-component, scanner, and YDEyes formats are classified only when the path,
  filename, or sampled content identifies Tencent/YunJing components. This
  avoids misclassifying unrelated application logs with the same timestamp
  layout; a heavily renamed and relocated file with no product marker may be
  reported as unknown.
- **Client timestamps have no timezone or offset.** `time_created` preserves
  the emitted wall-clock value as a naive timestamp; correlate it using the
  acquired host's timezone.
- **Semantic enrichment is best-effort.** Stable login, malware, quarantine,
  command-execution, blocklist, and account-detail messages populate dedicated
  columns; all other content remains fully available in `message`, `raw_line`,
  and `extra`. Physical continuation lines are attached to the preceding
  logical event rather than counted as parse errors.

## Windows Registry hive ingestion

- **Not a live merged registry.** seclogx does not simulate a running
  Windows OS's in-memory registry (no `HKLM`/`HKCU` aliasing, no
  volatile/`HKEY_CURRENT_CONFIG` keys, no class-name resolution). Every
  discovered hive is traversed and recoverable records are normalized into the
  `registry` table rooted at its own real logical path (`hive_root` +
  `key_path`, e.g. `HKEY_LOCAL_MACHINE\SOFTWARE\...`,
  `HKEY_USERS\<user>\...`) -- the standard way forensic registry tools
  (Registry Explorer, RegRipper, RECmd) already present hives, not a
  literal live registry object graph.
- **Binary hive parsing is delegated to `regipy`**, the same "trust a
  battle-tested library for a complex binary forensic format" choice
  already made for `.evtx` (via the `evtx` dependency) -- see
  `ingest/logsources/parsers/registry.py`.
- **Transaction-log (`.LOG1`/`.LOG2`) recovery is best-effort.** If a
  sibling `.LOG1` file is found next to a hive, seclogx tries to replay
  it (and `.LOG2`, if present) before parsing; if that fails for any
  reason (missing/corrupted log, unsupported log format), it falls back
  to parsing the raw hive as collected.
  `registry.transaction_log_applied = False` means recovery was not
  applied; it does not distinguish missing logs from replay failure. A hive
  collected "dirty" (writes pending in a transaction log that couldn't be
  replayed) may be missing its most recent changes.
- **Hive-type identification trusts the hive's own embedded original
  path** (stored in the hive header itself, e.g.
  `\SystemRoot\System32\Config\SOFTWARE`), not the on-disk filename --
  same "trust content, not filename" model every other seclogx parser
  uses, but note this means a hive whose embedded header has been
  tampered with (unusual, but possible) could misidentify.
- **`Case.suspicious_registry()` is a curated, non-exhaustive heuristic
  set** -- covers Run/RunOnce-style startup items, service ImagePath/
  ServiceDll, COM CLSID InprocServer32 hijacking, Winlogon Shell/
  Userinit/Notify tampering, AppInit_DLLs/AppCertDLLs injection, Image
  File Execution Options Debugger hijacking, and high-entropy binary
  values. Known gaps: WMI event subscriptions, additional LSA
  authentication/notification provider keys beyond the ones checked,
  Winsock LSP hijacking, and browser extension/COM add-in persistence
  paths not covered above -- same honesty standard as
  `SUSPICIOUS_ACTION_PATH_HINTS`/the Microsoft-task baseline for
  `scheduled_tasks`.
- **`entropy` is computed only for binary-typed values** (`REG_BINARY`,
  `REG_NONE`, and the resource-list types) from the full, untruncated raw
  bytes -- always populated regardless of size, but small values (a few
  bytes) can trivially read as "high entropy" purely from sample-size
  noise; `suspicious_registry()`'s `min_size` parameter (default 32
  bytes) exists specifically to filter that noise out before flagging.
- **`value_data_hex` stores at most the first 8 KiB of raw bytes as
  16,384 hexadecimal characters** (a
  pathologically large payload's hex isn't stored in full), but
  a binary value's `entropy`/`value_size` use the complete, uncapped bytes.
  For decoded strings/multi-strings, `value_size` is calculated from
  UTF-16 text lengths; it is not an exact original hive-cell byte count.
  Corrupt value/subkey iterators that end before their declared count
  mark the source partial; recovered records remain available.

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
  and `fits_in_memory()` falls back to a fixed 200 MiB absolute cap rather
  than assuming unlimited memory.

## Background ingest jobs and progress reporting

- **A `--background` job's on-disk status (`cases/<name>/jobs/<job_id>.json`)
  reflects the last progress update the job process actually made -- there
  is no separate liveness check.** If the background process is killed
  outright (`kill -9`, an OOM kill, the machine losing power) rather than
  raising a Python exception it can catch and record, `ingest-status` has
  no way to distinguish "still running" from "died mid-run" -- it will
  keep reporting whatever phase/counts were last written, indefinitely.
  An ingest that raises a normal Python exception *is* caught and recorded
  as `failed` with the exception message (see `cli/ingest_cmd.py`); this
  gap is specifically about the process disappearing without getting the
  chance to do that.
- **Job status files are never cleaned up automatically.** Every
  `--background` run leaves its `<job_id>.json` (and `.log`) behind under
  `cases/<name>/jobs/` indefinitely; on a case with many background
  imports over time this is a small but unbounded amount of bookkeeping.
  Delete old ones manually if it matters.
- **The `phase` field is coarse, not per-pipeline.** When EVTX and
  aux pipelines run concurrently under a workers budget above one (see below and
  [08. Performance & scale](guides/08_performance_and_scale.md)), one
  shared `phase` value (`scanning`/`staging`/`flattening`/`done`/`failed`)
  reports the more-advanced of the two pipelines' actual state rather
  than reporting each independently -- useful as a coarse progress signal,
  not as an exact per-table ETA. It only ever moves forward (a slower
  pipeline reporting `staging` after the other reached `flattening` no
  longer drags the reported phase backwards), which means it can say
  `flattening` while real staging work is still in flight.
- **Text preparation and parsing still require separate reads.**
  Normal UTF-8 text logs combine SHA-256 and strict whole-file encoding
  validation in one bounded pass, then parse in a second pass. If UTF-8
  fails, hashing still finishes and remaining encoding candidates are
  validated in their original order; UTF-8 is not retried. Scoped reuse
  matches both path and decoding policy. Identity, size and timestamps
  detect ordinary source changes, not an immutable evidence snapshot.
  Preparation read/change errors report a failed source; changes detected
  during parsing are fatal. EVTX, Registry and task XML retain separate
  hash/read paths. Storage and page-cache behavior affect all these costs.
- **`--background` only backgrounds the coordinator process.** In
  distributed mode, per-file parse work already runs on `seclogx worker`
  processes elsewhere; what blocked the terminal before was always the
  coordinator itself (discovery, dispatch, flatten, bookkeeping), and
  that's exactly what `--background` detaches -- there's no additional
  distributed-specific progress aggregation beyond what already existed.

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
  safe from lost metadata updates; this is not a lake transaction or a
  consistent query snapshot. A plain local file lock (used when no broker is configured) isn't
  a reliable cross-machine coordination mechanism over a network
  filesystem.
- **`case.json`, `staging/`, and `logs/` are never moved to S3, in any
  mode.** Only `lake/` (the Parquet payload) is affected by
  `SECLOGX_STORAGE_BACKEND` -- case metadata and ingest-time scratch space
  stay on whatever local/NFS directory `--case-root` points at. This is a
  deliberate scope boundary. Metadata is small, but staging can contain
  the full converted evidence set and must be reachable by parsing
  workers. Budget shared/local disk capacity accordingly.
- **`.sql()`/`.table()` (and the `Case` accessors built on them --
  `web_logs()`, `events()`, `timeline()`, etc.) materialize the entire
  result as one pandas DataFrame.** DuckDB's query execution underneath is
  lazy/out-of-core, but that doesn't help once the last step calls
  `fetchdf()` -- fine for a filtered/aggregated result, but web access/
  error logs especially can realistically reach terabyte scale across a
  case, well past what fits in memory as one DataFrame. Every such
  accessor has a `_chunks` sibling (`sql_chunks()`/`table_chunks()`,
  `query_chunks()`, `web_logs_chunks()`, `timeline_chunks()`, ...)
  returning an `Iterator[pd.DataFrame]` instead, with result delivery
  limited to approximately `chunksize` rows at a time -- use these for any table or
  query not already known to be small. The CLI (`query`/`table`/`tasks`/
  `timeline`) uses the chunked path automatically for both `--out` and
  the console preview. Row width, retaining/concatenating chunks, and
  DuckDB's execution state can still exhaust memory; chunked delivery
  is not a query RSS limit. Derived heuristics and Sigma hunts are not
  all covered by this chunked-accessor contract.
- **Streaming ingest does not impose a total-process memory ceiling.**
  Text-log and registry parsers emit completed rows to bounded Arrow IPC
  or gzip NDJSON staging;
  direct parser calls without `emit` retain the full-list compatibility
  API. Registry traversal uses a seekable file-backed hive instead of
  copying the complete hive into memory. Regipy transaction-log recovery
  still uses its potentially in-memory path, and an individual large
  registry value can allocate substantial memory. The adapter relies on
  regipy internals and its tests must be retained when upgrading regipy.
  Scheduled Task XML remains a whole-document parser, with an 8 MiB
  document limit enforced by ingest.
- **Record limits are explicit; large source files are not excluded.**
  The old 2 GiB non-EVTX source-file exclusion has been removed. Physical
  text lines are bounded at 8 Mi characters. Exchange/Tomcat logical
  records have an 8 Mi-character limit; database logical records also
  limit characters and line count (Oracle retains a 200-continuation-line
  bound). QCloud limits a logical record to 4 Mi characters or 100,000
  lines. CSV retains Python's field limit (normally 128 Ki characters),
  with an explicit exception on excess. Tomcat's 200-continuation-line
  bound raises before the incomplete current entry is emitted. Encoding
  after validation is strict; no replacement characters are silently
  inserted to handle later decode failures. QCloud requires a BOM before
  trying UTF-16; other text parsers preserve the legacy trial order.
- **`IngestOptions` limits each conversion's work, not total RSS.**
  Defaults are `memory_limit="2GB"`, `threads=2`,
  `staging_chunk_bytes=64 * 1024 * 1024` and
  `flatten_batch_bytes=256 * 1024 * 1024`, with `staging_format="auto"`.
  Auxiliary sources at least 16 MiB use Arrow/ZSTD1; smaller sources use
  gzip NDJSON, and either format can be explicitly selected. EVTX staging
  is unchanged. Arrow also uses a fixed 1 MiB output buffer per active
  staging writer. Byte targets use uncompressed JSON or Arrow buffer sizes.
  Shards/records are indivisible and may exceed a target;
  encoded records over 32 MiB are rejected. DuckDB's memory limit covers
  one conversion instance's managed allocations, not Python objects,
  parsing workers, native-library allocations or concurrent processes.
  `CONVERSION_LOCK` serializes ingest conversions in one coordinator or
  Notebook process, but not across independent processes or machines.
  Local `workers` is a total parsing budget across both pipelines;
  `workers=1` runs them serially in the calling process.
- **Automatic native parsing remains format-specific.** The main installation
  includes the Rust extension for compatible UTF-8 Common/Combined and IIS
  access logs. Default `parser_backend="auto"` uses Python when a format,
  encoding, syntax or runtime component is incompatible. Strict `native`
  fails on unsupported recognized auxiliary sources; `python` is an advanced
  diagnostic override. Capability fallback discards private output and
  reparses the entire source, which can add I/O. Reports distinguish
  `parser_backend` / `backend_reason` from `output_format` / `parquet_paths`.
  Source hashing, encoding preparation and canonical SQL remain. This does
  not make every format native or split a file across workers. Restart
  existing kernels after rebuilding or upgrading the extension. See
  [automatic parsing](guides/08_performance_and_scale.md#automatic-native-parsing).
- **Automatic direct Parquet conversion requires a compatible local context.**
  Default `direct_parquet=None` selects direct output with `keep_staging=False`,
  local execution/storage, no broker and backend `auto` or `native`. Other
  configurations automatically select staging. Explicit `True` rejects an
  incompatible configuration; explicit `False` forces staging. Compatible
  Web/IIS sources, including small files, use direct output. Other formats and
  whole-source compatibility replay retain the selected `staging_format`.
  Ordinary auxiliary jobs finish and their pool closes before direct sources
  run sequentially. The shared conversion lock keeps one DuckDB budget active
  per coordinator, without imposing a process-tree RSS cap. Hash/encoding
  pre-reading remains. Private output stays outside `lake/` until closure and
  source checks complete. Ordinary parse errors can publish a complete prefix
  as `partial`; zero recovered rows produce `failed` without output. Source
  changes, I/O, invalid native batches and conversion errors do not become
  compatibility replay. A crash can leave `_ingest_private` files without
  automatic recovery.

- **Direct publication depends on local filesystem operations.** Windows uses
  a rename that refuses to overwrite an existing destination. POSIX requires
  hard-link support and the private output and destination on the same
  filesystem. Unsupported or failed publication raises an error instead of
  copying or replaying through Python. These implementation paths do not imply
  validation of every platform and dependency combination.
- **Windows partition metadata is an optimization, not another schema.**
  Auxiliary staging collects canonical partition text before path escaping,
  limited to 4,096 distinct tuples / 1 MiB of encoded values per source.
  Missing legacy metadata, unsupported value types or exceeded limits
  fall back to DuckDB's `SELECT DISTINCT` scan before directory creation.
  That fallback's result depends on partition cardinality; EVTX retains
  its own partition scan.
- **Staged sources still finish staging before flattening.**
  Batch-isolated temporary directories prevent unrelated runs from
  overwriting staging files, and flatten handles bounded groups of
  shards. The local file-task queue has a pending-task bound, but there
  is no immediate flatten/disk-space backpressure pipeline. Staging disk
  usage can grow with the complete input, and discovery/manifest memory
  grows with file and shard count. Direct conversion bypasses shards only for
  eligible sources; it does not add backpressure to the remaining staged work.
- **Resume, cross-run idempotency and query snapshots are not provided.**
  Re-importing evidence can append duplicates; a failure after earlier
  flatten groups were written can leave partial data in the lake. Unique
  output filenames, metadata locking and isolated scratch space do not
  constitute an atomic dataset commit. Source-level publication on the direct
  path does not roll back earlier published sources if a later one fails.
  Arrow IPC staging still produces intermediate files before its conversion.
  No fixed throughput/RSS guarantee applies across arbitrary data sizes,
  formats or machines; EVTX native parsing and Registry recovery have
  additional format-specific resource requirements.
- **Staging is compressed and removed after successful conversion by default.**
  NDJSON uses gzip level 1 and Arrow IPC uses ZSTD level 1. Automatic direct
  output bypasses these files only for eligible local sources; other sources
  can still accumulate their complete staged dataset. `keep_staging=True`
  retains intermediates and automatically selects staging; source evidence is
  never deleted. Compression reduces disk requirements but still costs CPU,
  and cleanup after conversion does not remove peak staging usage. Retained
  shards help diagnosis but do not implement automatic resume. See
  [performance and scale](guides/08_performance_and_scale.md).
