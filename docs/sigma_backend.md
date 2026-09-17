# The Sigma backend, and how to extend it

`detect/backend.py` implements this project's custom DuckDB backend, modeled on the
public `pySigma-backend-sqlite` backend's token configuration (LIKE-based
string matching, `regexp_matches()` for regex, standard AND/OR/NOT).

## How a Sigma rule becomes a DuckDB query

1. **Field mapping** (`detect/pipeline.py` `FIELD_MAPPING`): Sigma's
   standard field taxonomy (`Image`, `CommandLine`, `ParentImage`, ...) is
   mapped to a full, parenthesized SQL expression against the `events`
   table, e.g. `Image` -> `(event_data ->> 'Image')`. The backend's
   `field_quote`/`field_escape` are left unset, so this mapped string is
   substituted as-is wherever a template needs `{field}`.

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

3. **Conversion** (`detect/backend.py` `DuckDBBackend`): the mapped,
   routed rule is converted to a bare boolean WHERE-clause fragment (not
   a full `SELECT`, deliberately -- stays decoupled from any particular
   view name). `detect/hunt.py` looks up the rule's target table via
   `LOGSOURCE_TABLE` and wraps the fragment as
   `SELECT * FROM <table> WHERE <fragment>`; if the case has no data in
   that table yet, the rule is reported as a failure ("case has no
   '<table>' table ingested"), not silently skipped.

4. **Result collection**: each rule query materializes a pandas DataFrame;
   matching frames are retained and concatenated into `HuntResults.matches`.
   The same event can appear once per matching rule. This path does not use
   chunked query delivery or the `search()` size guard. Distributed workers
   also return match frames to the coordinator. Ingest's `memory_limit`
   does not govern hunt connections or pandas allocations.

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
  only when the query executes. `rules validate` checks loading/conversion,
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
