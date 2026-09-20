# The Sigma backend, and how to extend it

`detect/backend.py` implements this project's custom DuckDB backend, modeled on the
public `pySigma-backend-sqlite` backend's token configuration (LIKE-based
string matching, `regexp_matches()` for regex, standard AND/OR/NOT).

## How a Sigma rule becomes a DuckDB query

1. **Field mapping** (`detect/pipeline.py` `FIELD_MAPPING`): the backend
   resolves original Sigma field names itself. Exact entries such as
   `Image` become trusted expressions such as `(event_data ->> 'Image')`.
   Unknown names must be simple identifiers (`[A-Za-z_][A-Za-z0-9_]*`) and
   are always double-quoted. External fields containing SQL syntax are
   rejected, including strings that resemble a trusted mapping expression.
   The processing pipeline never replaces untrusted fields with SQL strings.

   **Always parenthesize new field mappings.** DuckDB's
   `->`/`->>` operators don't bind as tightly as expected against
   `LIKE ... AND ...` in a compound WHERE clause; an unparenthesized
   mapping can misparse and fail at execution time with a confusing
   type-cast error rather than a clear syntax error.

2. **Logsource routing** (`detect/pipeline.py` `LOGSOURCE_ROUTES` +
   `LOGSOURCE_TABLE`): a Sigma rule's `logsource.category` (e.g.
   `process_creation`) is turned into an added `channel = '...' AND
   EventID = ...` condition via pySigma's `AddConditionTransformation`,
   scoped to that category via `LogsourceCondition`. Most `events`-backed
   categories route to Sysmon; `ps_script` and `ps_module` route to
   `Microsoft-Windows-PowerShell/Operational` events 4104 and 4103.
   `LOGSOURCE_TABLE` separately
   maps every supported category to the table it's hunted against --
   `events` for all of them except `webserver`, which targets `web_logs`
   (IIS/nginx/Apache/Tomcat/Exchange-HttpProxy access logs) and has no
   `LOGSOURCE_ROUTES` entry, since there's no channel/EventID concept to
   add a condition for.

3. **Conversion** (`detect/backend.py` `DuckDBBackend`): the
   routed rule is converted to a bare boolean WHERE-clause fragment (not
   a full `SELECT`, deliberately -- stays decoupled from any particular
   view name). `detect/hunt.py` looks up the rule's target table via
   `LOGSOURCE_TABLE` and wraps the fragment as
   `SELECT * FROM <table> WHERE <fragment>`; if the case has no data in
   that table yet, the rule is reported as a failure ("case has no
   '<table>' table ingested"), not silently skipped.

4. **Execution boundary** (`detect/security.py`): DuckDB parses the generated
   statement without executing it. The validator admits one plain SELECT
   over the expected case table, with only the supported predicate
   expressions/functions. Extra statements, subqueries, unions, relation
   changes and arbitrary functions are rejected. SQL string and regex
   literals escape apostrophes; regex backslashes retain their meaning.
   A dedicated connection permits declared input files and this hunt's
   private output directory, disables other external access and extension
   autoload/install, and locks configuration. Storage setup occurs before
   locking, including the configured S3 extension/credentials when needed.
   This is a restricted Sigma execution path, not a sandbox for arbitrary
   analyst SQL or a guarantee against a rule that is computationally expensive.

5. **Result collection** (`detect/hunt.py`, `detect/results.py`): a trusted
   COPY wrapper streams each validated query to Parquet using DuckDB's
   out-of-core execution. Python does not fetch each rule's complete rows.
   Each hunt connection uses a 512 MB managed-memory limit and two threads;
   these limits do not bound process RSS or the combined cost of multiple
   distributed workers. Workers return paths and counts rather than DataFrames,
   and require shared access to the case directory.

   All matches remain under `<case>/hunts/<run-id>/`, with `results.json`
   recording paths, exact counts, rule summaries and failures. The same
   event appears once per matching rule. Small results retain the complete
   `matches`/`to_dataframe()` interface, subject to aggregate limits of
   100,000 rows and 64 MiB of pandas data across all rules. Large results
   raise an explanatory `MemoryError` when either accessor is used; no
   rows are silently dropped. Use `preview()`, `iter_chunks()`, or `save()`.
   Preview metadata records total and preview counts and completeness.
   CSV export runs in DuckDB and replaces its destination only on success.
   `HuntResults.open(result_dir)` reopens a saved run after a Notebook restart.
   Parquet metadata guides Arrow batch sizes, and unusually wide batches
   are divided before pandas conversion. Row-group/dictionary decoding,
   a single indivisible record and conversion overhead can exceed a batch's
   byte target; this target is not a hard process-memory ceiling.

## Adding support for a new field or category

- New field used by a rule you want to run: add an entry to
  `FIELD_MAPPING` in `detect/pipeline.py`, parenthesized, pointing at the
  right column or JSON key for the table that rule's category targets
  (`event_data ->> '...'` for `events`; a direct `web_logs` column, e.g.
  `uri_stem`, for `webserver`).
- New logsource category targeting `events`: add an entry to
  `LOGSOURCE_ROUTES` with its `(channel, EventID)` target -- this also
  adds it to `LOGSOURCE_TABLE` automatically.
- New logsource category targeting a different table (`web_logs` or a
  future one): add an entry directly to `LOGSOURCE_TABLE` (skip
  `LOGSOURCE_ROUTES` unless that category also needs an added condition).
- `seclogx hunt` runs the bundled or a user-supplied Sigma rule directory
  against `events` and `web_logs` in v1 -- `scheduled_tasks`,
  `web_error_logs`, `exchange_message_tracking`/`exchange_logs`, the
  three Linux tables (`syslog`/`auditd_logs`/`journal_logs`), `db_logs`,
  `qcloud_logs`, and `registry` have no route in this project's
  `LOGSOURCE_TABLE` (Sigma's
  scheduled-task detections target the event log, not on-disk task
  definitions;
  Sigma's `registry_event`/`registry_add`/etc. categories model *live*
  registry-monitoring telemetry -- Sysmon EventID 12/13/14 fields like
  `TargetObject`/`EventType` -- not a static offline hive dump, so they
  don't fit `registry` either), so they're queried directly via
  SQL/`search()`, or via the lightweight `Case.suspicious_tasks()` /
  `Case.auth_events()` / `Case.suspicious_registry()` heuristics instead.
- Unknown fields can still convert to SQL as unmapped identifiers and fail
  only when the query executes, provided their names pass validation.
  They are quoted identifiers and cannot supply SQL expressions.
  `rules validate` checks loading/conversion,
  not a case's columns or the semantic correctness of a detection.
- After changing either, run `seclogx rules validate --rules <dir>`
  against the rules you care about to confirm they convert, then run
  `seclogx hunt <case> --rules <dir>` against a case with known-good data
  to sanity check real matches (see
  `test_hunt_catches_mimikatz_and_not_the_benign_record` in
  `tests/unit/test_hunt.py`, and the `synth_case` fixture it uses in
  `tests/conftest.py`, for the pattern: hand-craft one synthetic NDJSON
  record shaped like a real match, flatten it into a throwaway case, and
  confirm exactly the expected rule fires).
- When adding SQL functions or expression forms, update the explicit
  predicate allow-list in `detect/security.py` and add positive and
  adversarial tests. Do not bypass validation or restore unrestricted
  execution to support a new mapping.

## Adding more bundled rules

Rules are copied unmodified from `github.com/SigmaHQ/sigma` (Detection
Rule License 1.1 -- bundling/redistribution is fine with attribution
preserved). `data/sigma_rules/SOURCES.md` records the exact upstream path
and commit for every bundled rule; follow the same pattern (copy the
rule file as-is, don't hand-edit its content, record it in
`SOURCES.md`) when adding more.

## Not supported in v1

- Case-sensitive matching (`|cased`) and numeric comparison modifiers
  (`|lt`, `|gt`, ...) -- rules using them fail conversion explicitly.
- Sigma correlation rules.

Both fail loudly (`seclogx rules validate`, or as a `hunt` failure entry)
rather than silently producing a wrong query.
