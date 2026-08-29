"""Parse on-disk Windows Task Scheduler task definitions.

These are the `C:\\Windows\\System32\\Tasks\\**` files (extensionless on a
live system) -- a distinct, high-value persistence artifact, separate from
the Task Scheduler *event log* channel (Microsoft-Windows-TaskScheduler/
Operational), which is already covered generically by the existing EVTX
ingest since v1 parses every channel.

Triggers and Actions have many provider-specific shapes (TimeTrigger,
LogonTrigger, BootTrigger, EventTrigger, ComHandler, SendEmail, ...); rather
than hand-modeling each, every element is captured generically via
`_elem_to_dict` so nothing is silently dropped just because it isn't Exec/
TimeTrigger -- it is still fully queryable via `actions`/`triggers` JSON.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


class RejectedTaskXmlError(ValueError):
    pass


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _elem_to_dict(el: ET.Element):
    children = list(el)
    if not children:
        text = (el.text or "").strip()
        return text or None
    out: dict = {}
    for child in children:
        key = _strip_ns(child.tag)
        value = _elem_to_dict(child)
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


def _find_text(root: ET.Element, path: str) -> str | None:
    el = root.find(path)
    if el is None or el.text is None:
        return None
    text = el.text.strip()
    return text or None


def _derive_task_path(source_path: Path) -> str:
    parts = source_path.parts
    for i, part in enumerate(parts):
        if part.lower() == "tasks":
            return "\\" + "\\".join(parts[i + 1 :])
    return "\\" + source_path.name


def parse_task_xml(path: Path, host: str) -> dict:
    """Raises RejectedTaskXmlError / ValueError on anything that can't be
    trusted as a task definition; the caller reports this as a failed file,
    never a silent skip."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if "<!DOCTYPE" in text[:4096]:
        raise RejectedTaskXmlError("rejected: DOCTYPE declaration present (XXE guard)")

    root = ET.fromstring(text)
    if _strip_ns(root.tag) != "Task":
        raise ValueError(f"root element is <{root.tag}>, expected <Task>")

    settings = root.find(f"{TASK_NS}Settings")
    enabled = _find_text(root, f"{TASK_NS}Settings/{TASK_NS}Enabled") if settings is not None else None
    hidden = _find_text(root, f"{TASK_NS}Settings/{TASK_NS}Hidden") if settings is not None else None

    principal = root.find(f"{TASK_NS}Principals/{TASK_NS}Principal")
    principal_user_id = None
    principal_run_level = None
    principal_logon_type = None
    if principal is not None:
        principal_user_id = _find_text(principal, f"{TASK_NS}UserId")
        principal_run_level = _find_text(principal, f"{TASK_NS}RunLevel")
        principal_logon_type = _find_text(principal, f"{TASK_NS}LogonType")

    actions = []
    actions_el = root.find(f"{TASK_NS}Actions")
    if actions_el is not None:
        for action_el in list(actions_el):
            action = {"type": _strip_ns(action_el.tag)}
            action.update(_elem_to_dict(action_el) or {})
            actions.append(action)

    triggers = []
    triggers_el = root.find(f"{TASK_NS}Triggers")
    if triggers_el is not None:
        for trigger_el in list(triggers_el):
            trigger = {"type": _strip_ns(trigger_el.tag)}
            trigger.update(_elem_to_dict(trigger_el) or {})
            triggers.append(trigger)

    return {
        "host": host,
        "task_path": _derive_task_path(path),
        "task_name": path.name,
        "author": _find_text(root, f"{TASK_NS}RegistrationInfo/{TASK_NS}Author"),
        "description": _find_text(root, f"{TASK_NS}RegistrationInfo/{TASK_NS}Description"),
        "date_registered": _find_text(root, f"{TASK_NS}RegistrationInfo/{TASK_NS}Date"),
        "enabled": None if enabled is None else enabled.lower() == "true",
        "hidden": None if hidden is None else hidden.lower() == "true",
        "principal_user_id": principal_user_id,
        "principal_run_level": principal_run_level,
        "principal_logon_type": principal_logon_type,
        "actions": json.dumps(actions),
        "triggers": json.dumps(triggers),
    }


# Heuristics for a lightweight, non-Sigma "suspicious task" convenience
# (Case.suspicious_tasks() / `seclogx tasks --suspicious`) -- Sigma has no
# logsource category for on-disk task definitions (its scheduled-task
# detections target the event log, already covered by `events`).
SUSPICIOUS_ACTION_PATH_HINTS = ("\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\", "\\users\\public\\")
SUSPICIOUS_COMMAND_HINTS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
