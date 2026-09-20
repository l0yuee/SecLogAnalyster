"""Background process identity, heartbeat, cancellation and reconciliation."""

from __future__ import annotations

import json
import math
import os
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .common import now_iso
from .persistence import atomic_json

TERMINAL_PHASES = frozenset({"done", "failed", "interrupted", "cancelled"})
HEARTBEAT_INTERVAL = 2.0


class JobCancelledError(RuntimeError):
    pass


def _job_file(case_dir: Path, job_id: str, kind: str) -> Path:
    from .jobs import jobs_dir, validate_job_id
    return jobs_dir(case_dir) / f".{kind}" / f"{validate_job_id(job_id)}.json"


def register_spawned_process(case_dir: Path, job_id: str, pid: int) -> None:
    """A separate parent-written identity cannot overwrite child progress."""
    try:
        identity = process_identity(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return  # the child may already have written its final status
    atomic_json(_job_file(case_dir, job_id, "identities"), identity)


def _with_registered_identity(case_dir: Path, status: dict) -> dict:
    if status.get("pid") and status.get("process_created_at") is not None:
        return status
    try:
        identity = json.loads(_job_file(case_dir, status["job_id"], "identities").read_text(encoding="utf-8"))
        if not isinstance(identity, dict):
            return status
        return {**status, **identity}
    except (OSError, KeyError, json.JSONDecodeError):
        return status


def process_identity(pid: int | None = None) -> dict:
    process = psutil.Process(pid or os.getpid())
    return {"pid": process.pid, "process_created_at": process.create_time(), "hostname": socket.gethostname()}


def owned_process(status: dict):
    """Return only the exact recorded process; PID reuse is not ownership."""
    if status.get("hostname") != socket.gethostname():
        return None
    try:
        process = psutil.Process(int(status["pid"]))
        created_at = float(status["process_created_at"])
        if not math.isfinite(created_at) or abs(process.create_time() - created_at) > 0.001:
            return None
        return process if process.is_running() and process.status() != psutil.STATUS_ZOMBIE else None
    except (KeyError, TypeError, ValueError, OverflowError, psutil.NoSuchProcess):
        return None


def _live_children(case_dir: Path, status: dict) -> list:
    """Resolve recorded identities and worker leases after parent death."""
    identities = list(status.get("children") or [])
    for state_file in (case_dir / ".ingest").glob("*/state.json"):
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if state.get("job_id") != status["job_id"]:
                continue
            for lease in (state_file.parent / "workers").glob("*.json"):
                try:
                    identities.append(json.loads(lease.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
        except (OSError, json.JSONDecodeError):
            continue
    result = {}
    for identity in identities:
        if not isinstance(identity, dict):
            continue
        process = owned_process(identity)
        if process is not None:
            result[(process.pid, process.create_time())] = process
    return list(result.values())


def _committed_run(case_dir: Path, job_id: str) -> dict | None:
    try:
        meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        return next((run for run in reversed(meta.get("ingest_runs", [])) if run.get("job_id") == job_id), None)
    except (OSError, json.JSONDecodeError):
        return None


def reconcile_status(case_dir: Path, status: dict) -> dict:
    from .jobs import validate_job_id
    validate_job_id(status["job_id"])
    status = _with_registered_identity(case_dir, status)
    if status.get("phase") in TERMINAL_PHASES:
        return status
    if status.get("hostname") not in (None, socket.gethostname()):
        return status  # never interpret a remote PID using this host's process table
    if status.get("pid") and status.get("process_created_at") is not None:
        try:
            if owned_process(status) is not None:
                return status
        except psutil.AccessDenied:
            return status
    else:
        try:
            start = datetime.fromisoformat(status.get("updated_at") or status["started_at"])
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - start).total_seconds() < 60:
                return status  # allow a just-spawned child to register itself
        except (ValueError, KeyError, TypeError):
            return status
    # Re-read before persisting so a late child registration or terminal update
    # observed after the caller's snapshot wins over stale startup information.
    from .jobs import read_job_status
    latest = read_job_status(case_dir, status["job_id"], reconcile=False)
    if latest and latest.get("updated_at") != status.get("updated_at"):
        return latest
    result = dict(status)
    run = _committed_run(case_dir, status["job_id"])
    if run is not None:
        result.update(phase="done", committed=True, updated_at=now_iso(),
                      recovery_note="completion recovered from the committed case catalog")
    else:
        cancelled = _job_file(case_dir, status["job_id"], "cancel").exists()
        result.update(phase="cancelled" if cancelled else "interrupted", updated_at=now_iso(),
                      error="background process exited without committing; rerun ingest to retry safely")
        try:
            result["workers_running"] = len(_live_children(case_dir, status))
        except psutil.AccessDenied:
            result["workers_running"] = None
    atomic_json(case_dir / "jobs" / f"{status['job_id']}.json", result)
    return result


class JobHeartbeat:
    """One serialized status writer independent of parser progress frequency."""
    def __init__(self, case_dir: Path, job_id: str, initial: dict):
        from .jobs import validate_job_id
        self.case_dir = Path(case_dir)
        self.job_id = validate_job_id(job_id)
        self.status = {**initial, **process_identity(), "job_id": job_id}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="seclogx-job-heartbeat", daemon=True)

    def _write(self):
        self.status["updated_at"] = now_iso()
        self.status["heartbeat_at"] = self.status["updated_at"]
        children = []
        try:
            for child in psutil.Process().children(recursive=True):
                try:
                    children.append(process_identity(child.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        # Preserve previous identities too: an orphan may no longer appear in
        # the current process tree, but its creation time still proves ownership.
        existing = {(entry["pid"], entry["process_created_at"]): entry
                    for entry in self.status.get("children", [])}
        existing.update({(entry["pid"], entry["process_created_at"]): entry for entry in children})
        self.status["children"] = list(existing.values())
        atomic_json(self.case_dir / "jobs" / f"{self.job_id}.json", self.status)

    def __enter__(self):
        with self._lock:
            self._write()
            # Publish identity before checking intent. A requester that races
            # this check can now target this exact process; an earlier request
            # is handled here before any input is opened.
            if _job_file(self.case_dir, self.job_id, "cancel").exists():
                self.status.update(phase="cancelled", error="cancelled before ingest started")
                self._write()
                raise JobCancelledError(self.status["error"])
        self._thread.start()
        return self

    def update(self, snapshot: dict):
        with self._lock:
            self.status.update(snapshot)
            self._write()

    def _run(self):
        while not self._stop.wait(HEARTBEAT_INTERVAL):
            with self._lock:
                if self.status.get("phase") in TERMINAL_PHASES:
                    return
                try:
                    self._write()
                except OSError:
                    pass  # final main-thread write still propagates failure

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        self._thread.join(timeout=3)
        if exc is not None:
            with self._lock:
                if _committed_run(self.case_dir, self.job_id) is not None:
                    self.status.update(phase="done", committed=True, recovery_note="commit preceded process error")
                else:
                    self.status.update(phase="failed", error=str(exc))
                self._write()


def cancel_job(case_dir: Path, job_id: str) -> dict:
    from .jobs import read_job_status, write_job_status

    status = read_job_status(case_dir, job_id)
    if status is None:
        raise KeyError(f"unknown background job: {job_id}")
    if status.get("phase") == "done":
        return status
    if status.get("hostname") != socket.gethostname():
        raise RuntimeError("cancel the job on the host that started it")
    atomic_json(_job_file(case_dir, job_id, "cancel"), {"requested_at": now_iso()})
    # Refresh after publishing the request: the child may just have registered.
    status = read_job_status(case_dir, job_id) or status
    process = owned_process(status)
    descendants = _live_children(case_dir, status)
    if process is not None:
        command = process.cmdline()
        if job_id not in command or "seclogx.cli.main" not in command:
            raise RuntimeError("recorded process is not the expected background ingest command")
    elif not descendants:
        if status.get("phase") in TERMINAL_PHASES:
            return status
        # The child checks this durable request before starting work. Keep the
        # parent's startup document unchanged to avoid overwriting registration.
        return {**status, "phase": "cancelling", "cancel_requested": True}
    # Freeze the coordinator before collecting descendants so it cannot
    # spawn replacement workers while cancellation is terminating them.
    suspended = False
    try:
        if process is not None:
            process.suspend()
            suspended = True
            descendants.extend(process.children(recursive=True))
        descendants = list({(p.pid, p.create_time()): p for p in descendants}.values())
        for child in descendants:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        if process is not None:
            process.kill()
            suspended = False
        _, alive = psutil.wait_procs([*descendants, *([process] if process else [])], timeout=10)
        if any(p.is_running() and p.status() != psutil.STATUS_ZOMBIE for p in alive):
            raise RuntimeError("some ingest processes have not exited; cleanup has not started")
    except psutil.NoSuchProcess:
        pass
    finally:
        if suspended and process is not None:
            try:
                process.resume()
            except psutil.NoSuchProcess:
                pass
    run = _committed_run(case_dir, job_id)
    status.update(phase="done" if run else "cancelled", updated_at=now_iso(),
                  committed=run is not None,
                  workers_running=0,
                  error=None if run else "cancelled; uncommitted output is not visible")
    write_job_status(case_dir, job_id, status)
    return status


def cleanup_job_logs(case_dir: Path, retention_days: int = 7) -> list[str]:
    """Keep audit JSON; expire only old terminal-job console logs."""
    from .jobs import list_jobs, job_log_path

    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 0:
        raise ValueError("log retention days must be a nonnegative integer")
    cutoff = time.time() - retention_days * 86400
    removed = []
    for status in list_jobs(case_dir):
        if status.get("phase") not in TERMINAL_PHASES:
            continue
        try:
            if owned_process(status) is not None or _live_children(case_dir, status):
                continue
        except psutil.AccessDenied:
            continue
        path = job_log_path(case_dir, status["job_id"])
        if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff:
            path.unlink()
            removed.append(str(path))
    return removed
