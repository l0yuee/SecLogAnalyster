"""Reader leases protect immutable files retired by catalog maintenance."""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path

import psutil

from ..distributed.locking import get_case_lock
from ..paths import duckdb_path
from .job_control import owned_process, process_identity
from .persistence import atomic_json
from .transactions import catalog_files, read_metadata, _validate_removal


def capture_snapshot(case_dir: Path, config, backend) -> tuple[dict[str, list[str]], Path]:
    case_dir = Path(case_dir).resolve()
    with get_case_lock(case_dir, config):
        files = catalog_files(case_dir, backend)
        lease = case_dir / ".readers" / f"{uuid.uuid4().hex}.json"
        atomic_json(lease, {**process_identity(), "files": [p for paths in files.values() for p in paths]})
        return files, lease


def release_snapshot(connection, lease: Path) -> None:
    try:
        connection.close()
    finally:
        lease.unlink(missing_ok=True)


def retain_snapshot(case_dir: Path, config, files: dict[str, list[str]]) -> Path:
    """Give a streaming cursor a lease independent of its parent CaseDB."""
    case_dir = Path(case_dir).resolve()
    with get_case_lock(case_dir, config):
        lease = case_dir / ".readers" / f"{uuid.uuid4().hex}.json"
        atomic_json(lease, {**process_identity(), "files": [p for paths in files.values() for p in paths]})
        return lease


def cleanup_retired(case_dir: Path, config) -> list[str]:
    """Reclaim managed local files only after every registered reader exits."""
    if config.storage_backend != "local":
        return []
    case_dir = Path(case_dir).resolve()
    removed = []
    with get_case_lock(case_dir, config) as lock:
        meta = read_metadata(case_dir)
        readers = case_dir / ".readers"
        protected = set()
        for lease in readers.glob("*.json"):
            try:
                state = json.loads(lease.read_text(encoding="utf-8"))
                if state.get("hostname") != socket.gethostname():
                    return []
                if owned_process(state) is not None:
                    protected.update(state["files"])
                else:
                    lease.unlink()
            except (OSError, ValueError, KeyError, psutil.Error):
                return []  # uncertain readers never authorize data removal
        active = {str((case_dir / p).resolve()) for paths in meta.get("catalog", {}).values() for p in paths}
        remaining = []
        for entry in meta.get("retired_files", []):
            original_path = case_dir / entry["path"]
            path = original_path.resolve()
            if (str(path) in active or str(path) in protected
                    or not path.is_relative_to(case_dir / ".ingest")):
                remaining.append(entry)
                continue
            if Path(duckdb_path(path)).exists():
                _validate_removal(case_dir / ".ingest", original_path)
                Path(duckdb_path(original_path)).unlink()
                removed.append(str(path))
        meta["retired_files"] = remaining
        lock.assert_owned()
        atomic_json(case_dir / "case.json", meta)
    return removed
