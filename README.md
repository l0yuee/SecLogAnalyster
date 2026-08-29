# seclogx

Fast, pandas-friendly threat hunting over forensic acquisitions. Built for
DFIR/malware analysis workflows: point it at scattered acquisition
directories from multiple hosts, get back a queryable, huntable case
workspace instead of raw XML and inconsistent text logs.

- **Windows Event Log (`.evtx`) -- every channel** (Security, System,
  Application, Sysmon Operational, PowerShell Operational, WMI-Activity,
  ...) parsed generically, not a hand-picked subset.
- **Scheduled Tasks**: on-disk Task Scheduler XML definitions
  (`System32\Tasks\**`), a persistence artifact distinct from the Task
  Scheduler event log channel (also covered, via `.evtx`).
- **IIS logs**: W3C Extended Log Format access logs, plus HTTP.sys
  (HTTPERR) error logs.
- **Cross-platform web logs**: nginx, Apache, and Tomcat -- both major log
  categories: access logs (Common/Combined Log Format, unified with IIS
  into one queryable table) and error/diagnostic logs (each engine's
  native error-log format, unified into a second table).
- **Exchange logs**: Message Tracking (mail flow, first-class columns) plus
  every other Exchange CSV log type via a generic, nothing-dropped catchall.
- **Threat hunting built in**: Sigma rules (a curated bundled starter set,
  or your own) compiled to DuckDB SQL and run against the case, with
  MITRE ATT&CK tags surfaced on every match -- covers Windows Event Log
  and web access logs (`category: webserver`).
- **pandas-native**: every log family -- events, web access/error logs,
  Scheduled Tasks, Exchange logs -- is reachable as a `pandas.DataFrame`
  through a named accessor (`c.web_logs()`, `c.scheduled_tasks()`, ...),
  the same first-class treatment `events` gets, ready for a notebook.
- **Handles realistic case volumes (<100GB) on a single workstation**,
  lazily -- DuckDB + Parquet, no cluster required.
- **Never silently drops data.** Every parse error, partial file read,
  unrecognized log file, and unsupported Sigma rule is reported
  explicitly, not swallowed -- the direct answer to "importing into ELK
  silently drops records."

**Full user guide: [English](docs/user_guide.md) | [中文](docs/user_guide.zh-CN.md)**

See `docs/architecture.md` for how it works, `docs/schema.md` for the
normalized event schema, `docs/sigma_backend.md` for the detection engine,
and `docs/known_limitations.md` for known v1 scope decisions and edge
cases.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python >= 3.10. Run from a checkout of this repo (editable
install) so the bundled Sigma rules under `data/` are found.

## Quickstart

```bash
# Create a case and ingest from one or more forensic acquisition paths --
# .evtx, Scheduled Task definitions, IIS/nginx/Apache/Tomcat access logs,
# and Exchange CSV logs are all discovered and classified automatically in
# the same pass. Each --source can carry an explicit host label
# (PATH:HOST); if omitted, the source directory's name is used.
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01

# See what's in it
seclogx summary incident42
seclogx channels incident42
seclogx sources incident42        # row count per table: events, web_logs, scheduled_tasks, ...
seclogx tasks incident42 --suspicious

# Ad hoc SQL (the `events` table is the normalized, Hive-partitioned lake)
seclogx query incident42 "
  SELECT time_created, computer, event_data ->> 'Image' AS image, event_data ->> 'CommandLine' AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
  LIMIT 20
"

# Hunt with the bundled curated Sigma rule set (or --rules <your dir>)
seclogx hunt incident42

# Cross-host timeline, filterable, exportable
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

## Python / notebook usage

```python
from seclogx import Case

c = Case.open("incident42")

c.summary()                       # pandas.DataFrame
c.query("SELECT * FROM events WHERE event_id = 4688 LIMIT 10")
c.hunt().matches                  # matched events/web_logs, tagged with rule + ATT&CK ids
c.hunt().rule_summary             # one row per rule evaluated, with match counts
c.timeline(host="WKS01", event_id=[4624, 4625])
c.table_counts()                  # what log families this case has

# Every log family is a first-class, DataFrame-returning accessor -- same as events
c.web_logs(log_type="nginx")             # access logs: IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_error_logs(log_type="apache")      # error logs: nginx/Apache/Tomcat/IIS HTTPERR
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")
c.suspicious_tasks()              # heuristic triage over scheduled_tasks
c.db.table("web_logs")            # generic escape hatch: any table this case has, by name
```

## CLI reference

| Command | Purpose |
|---|---|
| `seclogx case init/list/info <name>` | Manage case workspaces |
| `seclogx ingest <case> --source PATH[:HOST]...` | Parse and normalize `.evtx` into the case |
| `seclogx query <case> "<SQL>"` | Ad hoc SQL against the case's `events` view |
| `seclogx summary <case>` / `channels <case>` | Quick overview of the `events` (Windows Event Log) table |
| `seclogx sources <case>` | Row count per table (events, web_logs, web_error_logs, scheduled_tasks, exchange_message_tracking, exchange_logs) |
| `seclogx table <case> <name>` | Full contents of any table this case has, as a DataFrame (CLI counterpart to `Case.web_logs()` etc.) |
| `seclogx tasks <case> [--suspicious]` | List ingested Scheduled Task definitions, optionally filtered by a built-in heuristic |
| `seclogx hunt <case> [--rules DIR] [--min-level LEVEL]` | Run Sigma rules, report matches + ATT&CK tags |
| `seclogx rules validate [--rules DIR]` | Check which rules convert vs are unsupported |
| `seclogx timeline <case> [--start/--end/--host/--channel/--event-id]` | Cross-host, filterable timeline over `events` |

Run any command with `--help` for full options.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT (see `LICENSE`) for seclogx's own code. Bundled Sigma rules under
`data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); see
`data/sigma_rules/SOURCES.md` for exact provenance per rule.
