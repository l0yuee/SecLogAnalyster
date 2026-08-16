# seclogx

Fast, pandas-friendly threat hunting over Windows Event Log (`.evtx`)
forensic acquisitions. Built for DFIR/malware analysis workflows: point it
at scattered acquisition directories from multiple hosts, get back a
queryable, huntable case workspace instead of raw XML.

- **All Windows Event Log channels** (Security, System, Application,
  Sysmon Operational, PowerShell Operational, WMI-Activity, ...) parsed
  generically, not a hand-picked subset.
- **Threat hunting built in**: Sigma rules (a curated bundled starter set,
  or your own) compiled to DuckDB SQL and run against the case, with
  MITRE ATT&CK tags surfaced on every match.
- **pandas-native**: every query, hunt, and timeline result is a
  `pandas.DataFrame`, ready for a notebook.
- **Handles realistic case volumes (<100GB) on a single workstation**,
  lazily -- DuckDB + Parquet, no cluster required.
- **Never silently drops data.** Every parse error, partial file read, and
  unsupported Sigma rule is reported explicitly, not swallowed -- the
  direct answer to "importing into ELK silently drops records."

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
# Create a case and ingest .evtx from one or more forensic acquisition
# paths. Each --source can carry an explicit host label (PATH:HOST); if
# omitted, the source directory's name is used.
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01

# See what's in it
seclogx summary incident42
seclogx channels incident42

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
c.hunt().matches                  # matched events, tagged with rule + ATT&CK ids
c.hunt().rule_summary             # one row per rule evaluated, with match counts
c.timeline(host="WKS01", event_id=[4624, 4625])
```

## CLI reference

| Command | Purpose |
|---|---|
| `seclogx case init/list/info <name>` | Manage case workspaces |
| `seclogx ingest <case> --source PATH[:HOST]...` | Parse and normalize `.evtx` into the case |
| `seclogx query <case> "<SQL>"` | Ad hoc SQL against the case's `events` view |
| `seclogx summary <case>` / `channels <case>` | Quick overview of what's in a case |
| `seclogx hunt <case> [--rules DIR] [--min-level LEVEL]` | Run Sigma rules, report matches + ATT&CK tags |
| `seclogx rules validate [--rules DIR]` | Check which rules convert vs are unsupported |
| `seclogx timeline <case> [--start/--end/--host/--channel/--event-id]` | Cross-host, filterable timeline |

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
