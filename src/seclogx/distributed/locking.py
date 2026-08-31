"""Protects `case.json`'s read-modify-write cycle (`Case._load_meta` /
`Case._save_meta`, used by `Case.ingest()`) from concurrent-writer races.

Not purely a cluster-mode concern: before this module existed, two
`seclogx ingest` runs against the same case racing (even on one machine,
e.g. two terminals) would silently lose one run's `ingest_runs`/`hosts`
bookkeeping -- a plain `write_text()` with no lock. `LocalCaseLock` fixes
that unconditionally, stdlib-only (no new dependency for the
default/local path -- `fcntl.flock` on POSIX, `msvcrt.locking` on
Windows, the same per-platform-stdlib approach `memcheck.py` already uses
rather than reaching for a new dependency). `RedisCaseLock` is used
instead once a broker is configured (`ClusterConfig.is_distributed`) -- a
POSIX file lock over a network filesystem is unreliable for coordinating
truly separate machines, whereas the same Redis a distributed setup
already needs for its job queue gives a proper cross-machine lock at no
extra infrastructure cost.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Protocol

from ..errors import ClusterConfigError
from .config import ClusterConfig


class CaseLock(Protocol):
    def __enter__(self) -> "CaseLock": ...
    def __exit__(self, *exc) -> None: ...


class LocalCaseLock:
    def __init__(self, case_dir: Path, timeout: float = 30.0):
        self._path = Path(case_dir) / ".case.lock"
        self._timeout = timeout
        self._fh = None

    def __enter__(self) -> "LocalCaseLock":
        self._fh = open(self._path, "a+")
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                self._lock_file(self._fh)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    raise TimeoutError(f"timed out waiting for the case lock at {self._path}")
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        try:
            self._unlock_file(self._fh)
        finally:
            self._fh.close()

    @staticmethod
    def _lock_file(fh) -> None:
        try:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)

    @staticmethod
    def _unlock_file(fh) -> None:
        try:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except ImportError:
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)


class RedisCaseLock:
    def __init__(self, case_dir: Path, broker_url: str, timeout: float = 30.0):
        try:
            import redis
        except ImportError as e:  # pragma: no cover - exercised only when redis missing
            raise ClusterConfigError(
                "distributed case-metadata locking requires the 'cluster' extra: pip install 'seclogx[cluster]'"
            ) from e
        client = redis.from_url(broker_url)
        key = f"seclogx:case-lock:{Path(case_dir).resolve()}"
        self._lock = client.lock(key, timeout=timeout)

    def __enter__(self) -> "RedisCaseLock":
        self._lock.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self._lock.release()


def get_case_lock(case_dir: Path, cluster_config: ClusterConfig | None = None) -> CaseLock:
    cluster_config = cluster_config or ClusterConfig.from_env()
    if cluster_config.is_distributed:
        return RedisCaseLock(case_dir, cluster_config.broker_url)
    return LocalCaseLock(case_dir)
