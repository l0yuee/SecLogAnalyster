# seclogx documentation

**Language: English | [中文](index.zh-CN.md)**

Fast, pandas-friendly threat hunting and analysis over forensic log
acquisitions: Windows Event Log, Scheduled Tasks, IIS/nginx/Apache/Tomcat
web access & error logs, and Exchange logs.

## Guides

1. **[Getting started](guides/01_getting_started.md)** -- what seclogx is
   for, installation, the case workspace, and a quickstart.
2. **[Log types and schema](guides/02_log_types_and_schema.md)** -- what
   each of the six tables holds, what to look for, and which fields to
   search on.
3. **[Querying and search](guides/03_querying_and_search.md)** -- raw
   SQL, the no-SQL `search()` interface, and bounded-memory delivery.
4. **[Threat hunting](guides/04_threat_hunting.md)** -- Sigma rules,
   ATT&CK tagging, and extending detection.
5. **[CLI reference](guides/05_cli_reference.md)** -- every `seclogx`
   subcommand.
6. **[Python / notebook API](guides/06_python_api.md)** -- the `Case` /
   `CaseDB` API surface.
7. **[Recipes](guides/07_recipes.md)** -- copy-pasteable analyst
   workflows.
8. **[Performance and scale](guides/08_performance_and_scale.md)** --
   what to expect at real-world case volumes.
9. **[Troubleshooting, FAQ, and known limitations](guides/09_faq_and_limitations.md)**
   -- common errors explained, and a pointer to the full limitations list.

## Internal design reference

- **[architecture.md](architecture.md)** -- how the two ingest pipelines
  (EVTX and non-EVTX), the Parquet lake, and the query/search/detection
  layers fit together.
- **[schema.md](schema.md)** -- the exact column-by-column reference for
  every table.
- **[sigma_backend.md](sigma_backend.md)** -- how the custom DuckDB Sigma
  backend works, and how to extend field mappings.
- **[known_limitations.md](known_limitations.md)** -- the complete,
  current list of v1 scope decisions and edge cases. This is the source
  of truth; the guides above link to it rather than restating it.

See the repo root `README.md` for install-in-30-seconds instructions and
a condensed CLI/API cheat sheet.
