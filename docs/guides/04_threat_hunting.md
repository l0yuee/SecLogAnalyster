# 4. Threat hunting

**Language: English | [中文](04_threat_hunting.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | 04. Threat hunting | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

## Understanding hunt results and ATT&CK tags

`seclogx hunt` runs every Sigma rule it can load and convert, and reports
three things:

- **Matches** (`results.matches`): the actual matched event rows, each
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
event fields specifically (process creation, network connections, file
events, registry changes, image loads, DNS queries, named pipes,
PowerShell script blocks, process access) -- it will only find things if
Sysmon was actually running and its logs were ingested. It is a curated
starting point, not exhaustive; see "Extending detection" below to add
more.

`hunt` also supports Sigma's `category: webserver` rules (against
`web_logs`, i.e. **access** logs), for supplying your own IIS/nginx/Apache
webshell or exploitation-pattern rules -- none are bundled by default in
v1. There is no Sigma logsource category for on-disk Scheduled Task
definitions, web application **error** logs (`web_error_logs`), or
Exchange message tracking, so those aren't part of a Sigma hunt; use
`Case.suspicious_tasks()` / `seclogx tasks --suspicious` for tasks, and
plain SQL/search (see [07. Recipes](07_recipes.md)) for `web_error_logs`
and Exchange.

## Extending detection: custom rules and fields

Point `--rules` / `rules_dir=` at any directory of standard Sigma YAML
rules -- they don't have to come from the bundled set. Before relying on
a new rule set, run:

```bash
seclogx rules validate --rules /path/to/your/rules
```

This reports, per rule, whether it converts successfully. Common reasons
a rule won't convert out of the box:

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
