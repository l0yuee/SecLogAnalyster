"""Compare an ingested Scheduled Task against a bundled reference list of
well-known default Windows tasks, to catch a specific persistence pattern:
modifying, or masquerading as, an existing legitimate Microsoft task
(MITRE ATT&CK T1053.005) rather than registering an obviously new one.

The bundled baseline (`data/scheduled_tasks/known_microsoft_tasks.json`) is
a curated, best-effort reference -- not exhaustive, not pinned to a
specific Windows version/edition, and not a code-signing or hash check. It
only asks "does this known task's action point somewhere it should never
point" -- the same spirit as `SUSPICIOUS_ACTION_PATH_HINTS`, just anchored
to a specific known task path instead of a generic path/LOLBin hint. See
docs/known_limitations.md.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from ....config import BUNDLED_SCHEDULED_TASK_BASELINE

# Common environment-variable forms seen in real Task XML `Command`/
# `Arguments` values, normalized to their typical literal expansion so a
# baseline entry only has to list one literal form and still match either.
_ENV_VAR_EXPANSIONS = {
    "%systemroot%": r"c:\windows",
    "%windir%": r"c:\windows",
    "%programfiles(x86)%": r"c:\program files (x86)",
    "%programfiles%": r"c:\program files",
    "%systemdrive%": "c:",
}


def _normalize(command: str) -> str:
    text = command.strip().strip('"').lower()
    for var, expansion in _ENV_VAR_EXPANSIONS.items():
        text = text.replace(var, expansion)
    return text


@lru_cache(maxsize=1)
def _load_baseline(path: Path = BUNDLED_SCHEDULED_TASK_BASELINE) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["task_path"].strip().lower(): entry for entry in data.get("tasks", [])}


def classify_against_baseline(task_path: str | None, action_command: str | None) -> str | None:
    """A human-readable mismatch reason if `task_path` matches a known
    baseline entry but `action_command` doesn't start with any of that
    entry's expected executable location(s); otherwise None -- no baseline
    entry for this path, no Exec action to compare (e.g. a ComHandler-only
    task), or the action matches as expected."""
    if not task_path or not action_command:
        return None
    entry = _load_baseline().get(task_path.strip().lower())
    if entry is None:
        return None
    expected = entry.get("expected_command_prefixes", [])
    normalized_command = _normalize(action_command)
    if any(normalized_command.startswith(p.lower()) for p in expected):
        return None
    return (
        f"known Microsoft task path {task_path!r} has an action executable outside "
        f"its expected location(s) ({', '.join(expected)})"
    )
