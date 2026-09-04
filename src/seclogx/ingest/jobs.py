"""Progress tracking during one `Case.ingest()` run, and on-disk status
for background (`--background`) ingest jobs.

`ProgressReporter` is the single object threaded through `scan.scan_sources()`
and both orchestrators (`ingest/evtx/orchestrator.py`,
`ingest/logsources/orchestrator.py`) during one ingest run. Since
`Case.ingest()` now runs both orchestrators concurrently (see case.py), this
object is genuinely shared across threads -- every mutating method takes a
lock, which also has the side effect of serializing calls into `on_update`
(so a caller rendering a live display, or writing a JSON file, never has to
worry about concurrent re-entrancy on its own).

`write_job_status`/`read_job_status`/`list_jobs` are the on-disk side: one
small JSON snapshot per background job under `<case_dir>/jobs/<job_id>.json`,
written atomically (temp file + `os.replace`) so a concurrent reader
(`seclogx ingest-status`) never observes a half-written file.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

JOBS_DIRNAME = "jobs"

PHASE_SCANNING = "scanning"
PHASE_STAGING = "staging"
PHASE_FLATTENING = "flattening"
PHASE_DONE = "done"
PHASE_FAILED = "failed"


def jobs_dir(case_dir: Path) -> Path:
    return Path(case_dir) / JOBS_DIRNAME


def job_status_path(case_dir: Path, job_id: str) -> Path:
    return jobs_dir(case_dir) / f"{job_id}.json"


def job_log_path(case_dir: Path, job_id: str) -> Path:
    return jobs_dir(case_dir) / f"{job_id}.log"


def write_job_status(case_dir: Path, job_id: str, status: dict) -> None:
    d = jobs_dir(case_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = job_status_path(case_dir, job_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)  # atomic on both POSIX and Windows


def read_job_status(case_dir: Path, job_id: str) -> dict | None:
    path = job_status_path(case_dir, job_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A reader can race a concurrent write to the same path in theory
        # (os.replace is atomic, but a prior read of a since-deleted file
        # or a transient decode hiccup shouldn't crash `ingest-status`);
        # the next poll simply tries again.
        return None


def list_jobs(case_dir: Path) -> list[dict]:
    d = jobs_dir(case_dir)
    if not d.exists():
        return []
    statuses = []
    for p in sorted(d.glob("*.json")):
        try:
            statuses.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    statuses.sort(key=lambda s: s.get("started_at") or "", reverse=True)
    return statuses


@dataclass
class ProgressReporter:
    """Tracks one ingest run's progress and reports it via `on_update`.

    `on_update` receives the full current snapshot dict every time it's
    called (not a diff) -- cheap to build (a handful of ints plus a small
    per-table dict), so the caller (a live Rich display, or a JSON-file
    writer for a background job) can just re-render/re-write it whole
    rather than tracking incremental state of its own.

    Emission is throttled (`min_interval` seconds, or `min_count_interval`
    completed files, whichever comes first) so a batch with a huge file
    count doesn't turn every single result into a render/disk write --
    phase transitions and the terminal state always emit immediately
    regardless of throttling.
    """

    on_update: Callable[[dict], None] | None = None
    min_interval: float = 0.3
    min_count_interval: int = 25

    phase: str = PHASE_SCANNING
    files_scanned: int = 0
    evtx_discovered: int = 0
    aux_discovered: int = 0
    evtx_staged: int = 0
    aux_staged: int = 0
    files_ok: int = 0
    files_partial: int = 0
    files_failed: int = 0
    files_unknown: int = 0
    rows_written: dict = field(default_factory=dict)
    error: str | None = None

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    # Seeded to "now" (not 0.0) at construction: otherwise the very first
    # call would see an enormous elapsed time since epoch-zero and bypass
    # time-based throttling regardless of min_interval.
    _last_emit_ts: float = field(default_factory=time.monotonic, repr=False, compare=False)
    _last_emit_count: int = field(default=0, repr=False, compare=False)

    def snapshot(self) -> dict:
        return {
            "phase": self.phase,
            "files_scanned": self.files_scanned,
            "evtx_discovered": self.evtx_discovered,
            "aux_discovered": self.aux_discovered,
            "evtx_staged": self.evtx_staged,
            "aux_staged": self.aux_staged,
            "files_ok": self.files_ok,
            "files_partial": self.files_partial,
            "files_failed": self.files_failed,
            "files_unknown": self.files_unknown,
            "rows_written": dict(self.rows_written),
            "error": self.error,
        }

    def _emit(self, force: bool = False) -> None:
        if self.on_update is None:
            return
        now = time.monotonic()
        total = self.evtx_staged + self.aux_staged
        if not force and (now - self._last_emit_ts) < self.min_interval and (
            total - self._last_emit_count
        ) < self.min_count_interval:
            return
        self._last_emit_ts = now
        self._last_emit_count = total
        self.on_update(self.snapshot())

    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase
            self._emit(force=True)

    def on_scanned(self, count: int) -> None:
        with self._lock:
            self.files_scanned = count
            self._emit()

    def set_discovered(self, evtx: int, aux: int) -> None:
        with self._lock:
            self.evtx_discovered = evtx
            self.aux_discovered = aux
            self._emit(force=True)

    def on_evtx_result(self, staged) -> None:
        with self._lock:
            self.evtx_staged += 1
            self._tally(staged.status)
            self._emit()

    def on_aux_result(self, staged) -> None:
        with self._lock:
            self.aux_staged += 1
            self._tally(staged.status)
            self._emit()

    def _tally(self, status: str) -> None:
        from .common import StageStatus

        if status == StageStatus.OK:
            self.files_ok += 1
        elif status == StageStatus.PARTIAL:
            self.files_partial += 1
        elif status == StageStatus.FAILED:
            self.files_failed += 1
        elif status == StageStatus.UNKNOWN:
            self.files_unknown += 1

    def on_table_flattened(self, table: str, rows: int) -> None:
        with self._lock:
            self.rows_written[table] = self.rows_written.get(table, 0) + rows
            self._emit(force=True)

    def finish(self, error: str | None = None) -> None:
        with self._lock:
            self.phase = PHASE_FAILED if error else PHASE_DONE
            self.error = error
            self._emit(force=True)


__all__ = [
    "JOBS_DIRNAME",
    "PHASE_DONE",
    "PHASE_FAILED",
    "PHASE_FLATTENING",
    "PHASE_SCANNING",
    "PHASE_STAGING",
    "ProgressReporter",
    "job_log_path",
    "job_status_path",
    "jobs_dir",
    "list_jobs",
    "read_job_status",
    "write_job_status",
]
