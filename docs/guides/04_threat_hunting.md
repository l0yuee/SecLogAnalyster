# 4. Threat hunting

**Language: English | [中文](04_threat_hunting.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | 04. Threat hunting | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

## Understanding hunt results and ATT&CK tags

`seclogx hunt` runs every Sigma rule it can load and convert, and reports
three things:

- **Matches** (`results.matches` for small hunts): the actual matched event rows, each
  tagged with `sigma_rule_id`, `sigma_rule_title`, `sigma_level`, and
  `sigma_attack_ids` (a comma-separated list of MITRE ATT&CK technique
  IDs, e.g. `T1003.001, T1003.002`).
- **Rule summary** (`results.rule_summary`): one row *per rule
  evaluated* (not per match) -- title, level, author, match count,
  ATT&CK tags, references. A rule with `matches == 0` simply didn't fire
  against this case's data; that's a normal, expected outcome for most
  rules most of the time.
- **Skipped / failed** (`results.skipped`, `results.failures`): rules
  that couldn't be loaded/routed (unsupported logsource category) or
  couldn't be converted/executed (unsupported Sigma feature, or a field
  this case's pipeline doesn't map yet). Always check these are empty or
  understood -- see `seclogx rules validate` and
  `docs/sigma_backend.md` if you need to extend field mappings.

ATT&CK technique names/tactics are enriched from a small bundled lookup
(`data/attack/techniques.json`) covering the techniques used by the
bundled rule set -- not the full ATT&CK framework. Unknown IDs still
show up as bare `TXXXX` identifiers.

The bundled rule set (37 rules, `data/sigma_rules/`) targets **Sysmon**
telemetry and **PowerShell Operational** events. Sysmon categories need
the corresponding collected Sysmon logs; `ps_script`/`ps_module` use
PowerShell events 4104/4103 independently of Sysmon. Ingested Security
4688 events do not substitute for the Sysmon process-creation route.
The rules are a curated starting point, not exhaustive coverage.

`hunt` also supports Sigma's `category: webserver` rules (against
`web_logs`, i.e. **access** logs), for supplying your own IIS/nginx/Apache
webshell or exploitation-pattern rules -- none are bundled by default in
v1. This project's routing does not cover on-disk Scheduled Task
definitions, web application **error** logs (`web_error_logs`), Exchange
message tracking, Linux text logs, database logs (`db_logs`), Tencent
client logs (`qcloud_logs`), Aegis client logs (`aegis_logs`), or the Windows Registry
(`registry` -- Sigma's registry categories model *live* monitoring
telemetry, not a static offline hive dump), so those aren't part of a
Sigma hunt; use `Case.suspicious_tasks()` / `seclogx tasks --suspicious`
for tasks, `Case.suspicious_registry()` / `seclogx registry --suspicious`
for the registry, and plain SQL/search (see [07. Recipes](07_recipes.md))
for `web_error_logs`, Exchange, and `db_logs`.

## Working with large results in Jupyter

`c.hunt()` automatically saves complete matches as Parquet under the case's
`hunts/` directory. Small results remain available as a complete DataFrame
through `results.matches` or `results.to_dataframe()`. If the combined
results exceed the automatic memory or row budget, those accessors raise
an explanatory `MemoryError`. Import and hunt settings do not need to be
tuned to activate this behavior.

```python
results = c.hunt()
print(results.summary_text())
print(results.total_matches)       # exact count across evaluated rules
display(results.preview(100))      # a preview, not the complete result

results.save("all-matches.csv")    # streams every match, even for large hunts
for chunk in results.iter_chunks():
    # Analyze or aggregate this chunk, then discard it.
    print(chunk["sigma_rule_title"].value_counts())
```

`preview()` returns at most the requested rows within its preview byte
budget. Its DataFrame `attrs` contains `total_matches`, `preview_rows` and
`complete`; the default preview requests 100 rows. `is_spilled` indicates
that the full result is too large for automatic DataFrame loading.
`iter_chunks()` reads all saved rows with bounded batch sizes. Keep only
the aggregates you need instead of collecting every chunk in a list.
Arrow batch sizes adapt to Parquet metadata, with wide batches split before
pandas conversion. A single exceptionally wide record or Parquet dictionary
decoding can still require more memory than a batch's byte target.

Saved runs survive closing the Case or restarting Jupyter:

```python
from seclogx.detect import HuntResults

saved_directory = results.result_dir  # retain this path for a later session
reopened = HuntResults.open(saved_directory)
display(reopened.preview())
```

One event can appear once for each matching rule, so the total count is a
count of rule matches, not unique events. Full results can require substantial
disk space. Failed rules remain visible in `failures`; their partial output
is not included. Each local hunt reads one committed case snapshot. Distributed
workers capture their own committed snapshots, so run after imports finish
when all workers must evaluate the same dataset. Distributed workers return
artifact paths and counts and need shared access to the case directory.

External rule fields are validated and quoted; only the project's field
mapping may introduce SQL expressions. Generated queries are restricted to
the expected case table and supported predicates on a dedicated connection.
Additional SQL statements, arbitrary functions and unrelated file access
are rejected. These controls do not judge whether a detection is useful or
inexpensive; review its match counts and failures.

## Extending detection: custom rules and fields

Point `--rules` / `rules_dir=` at any directory of standard Sigma YAML
rules -- they don't have to come from the bundled set. Before relying on
a new rule set, run (a supplied directory replaces the bundled selection):

```bash
seclogx rules validate --rules /path/to/your/rules
```

This reports, per rule, whether it loads and converts successfully. It
does not execute against a case: an unmapped field can convert successfully
and then fail at query time. Common reasons a rule needs adaptation:

- **It uses a Sigma field seclogx doesn't map yet.** Add it to
  `FIELD_MAPPING` in `src/seclogx/detect/pipeline.py` (see
  `docs/sigma_backend.md` for the exact pattern -- field expressions
  must be parenthesized).
- **It targets a logsource category seclogx doesn't route.** Add it to
  `LOGSOURCE_ROUTES` (if it targets `events`) or `LOGSOURCE_TABLE` (if it
  targets a different table, e.g. a new `web_logs`-backed category) in
  the same file.
- **It uses an unsupported Sigma feature** (case-sensitive `|cased`
  matching, numeric comparison modifiers, correlation rules) -- not
  supported in v1; see `docs/known_limitations.md`.

After changing the mapping, re-run `rules validate`, then `hunt` against
a case with data you expect to match, to confirm end to end.

Next: [05. CLI reference](05_cli_reference.md) for the full `hunt`/`rules
validate` command options.
