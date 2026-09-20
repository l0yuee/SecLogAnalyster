"""Worker leases prevent cleanup beneath a surviving orphan worker."""

from __future__ import annotations

import functools
import json
import socket
import uuid
from pathlib import Path

from ..distributed.locking import LocalCaseLock
from .job_control import owned_process, process_identity
from .persistence import atomic_json


def worker_workspace(path: Path) -> Path | None:
    for parent in (Path(path), *Path(path).parents):
        if parent.parent.name == ".ingest":
            return parent
    return None


def active_workers(workspace: Path) -> bool:
    root = workspace / "workers"
    if not root.exists():
        return False
    for path in root.glob("*.json"):
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("hostname") != socket.gethostname() or owned_process(state) is not None:
            return True
    return False


def workspace_worker(function):
    """Staging functions receive their output directory as argument two."""
    @functools.wraps(function)
    def wrapped(discovered, staging_dir, *args, **kwargs):
        workspace = worker_workspace(staging_dir)
        if workspace is None:
            return function(discovered, staging_dir, *args, **kwargs)
        activity = workspace / "activity"
        activity.mkdir(exist_ok=True)
        lease = workspace / "workers" / f"{uuid.uuid4().hex}.json"
        with LocalCaseLock(activity):
            state = json.loads((workspace / "state.json").read_text(encoding="utf-8"))
            if state.get("phase") != "running":
                raise RuntimeError("ingest workspace no longer accepts worker output")
            if state.get("hostname") == socket.gethostname() and owned_process(state) is None:
                raise RuntimeError("ingest coordinator exited before worker start")
            atomic_json(lease, process_identity())
        try:
            return function(discovered, staging_dir, *args, **kwargs)
        finally:
            lease.unlink(missing_ok=True)
    return wrapped
