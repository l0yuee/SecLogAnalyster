# The Sigma backend, and how to extend it

No official DuckDB (or generic ANSI-SQL) pySigma backend exists, so
`detect/backend.py` implements a small custom one, closely modeled on the
public `pySigma-backend-sqlite` backend's token configuration (LIKE-based
string matching, `regexp_matches()` for regex, standard AND/OR/NOT).

## How a Sigma rule becomes a DuckDB query

1. **Field mapping** (`detect/pipeline.py` `FIELD_MAPPING`): Sigma's
   standard field taxonomy (`Image`, `CommandLine`, `ParentImage`, ...) is
   mapped to a full, parenthesized SQL expression against the `events`
   table, e.g. `Image` -> `(event_data ->> 'Image')`. The backend's
   `field_quote`/`field_escape` are left unset, so this mapped string is
   substituted as-is wherever a template needs `{field}`.

   **Always parenthesize new field mappings.** Empirically, DuckDB's
   `->`/`->>` operators don't bind as tightly as expected against
   `LIKE ... AND ...` in a compound WHERE clause; an unparenthesized
   mapping can misparse and fail at execution time with a confusing
   type-cast error rather than a clear syntax error.

2. **Logsource routing** (`detect/pipeline.py` `LOGSOURCE_ROUTES` +
   `LOGSOURCE_TABLE`): a Sigma rule's `logsource.category` (e.g.
   `process_creation`) is turned into an added `channel = '...' AND
   EventID = ...` condition via pySigma's `AddConditionTransformation`,
   scoped to that category via `LogsourceCondition`. v1 routes every
   `events`-backed category to its Sysmon equivalent (see
   `docs/known_limitations.md` for why). `LOGSOURCE_TABLE` separately
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
- `seclogx hunt` only ever runs bundled + user-supplied Sigma rules
  against `events` and `web_logs` in v1 -- `scheduled_tasks`,
  `web_error_logs`, `exchange_message_tracking`/`exchange_logs`, and the
  three Linux tables (`syslog`/`auditd_logs`/`journal_logs`) have no
  Sigma logsource category that fits (Sigma's scheduled-task detections
  target the event log, not on-disk task definitions; there's no
  standard Sigma category for web error/diagnostic logs or for these
  Linux formats either), so they're queried directly via SQL/`search()`,
  or via the lightweight `Case.suspicious_tasks()` / `Case.auth_events()`
  heuristics instead.
- After changing either, run `seclogx rules validate --rules <dir>`
  against the rules you care about to confirm they convert, then run
  `seclogx hunt <case> --rules <dir>` against a case with known-good data
  to sanity check real matches (see the mimikatz-record test in this
  project's development history for the pattern: hand-craft one
  synthetic NDJSON record shaped like a real match, flatten it into a
  throwaway case, and confirm exactly the expected rule fires).

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
