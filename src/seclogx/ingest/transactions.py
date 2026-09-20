"""Immutable ingest outputs published by one atomic case metadata update.

The case catalog is the visibility boundary. A partially written workspace
is never queried. Existing lake files are adopted without rewriting data.
Source identity includes provenance and decoding semantics, not just bytes.
"""

from __future__ import annotations

import dataclasses
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import uuid
from pathlib import Path
from urllib.parse import unquote
from urllib.parse import urlsplit

from ..distributed.locking import LocalCaseLock, get_case_lock
from ..distributed.storage import get_storage_backend
from ..paths import duckdb_path
from .common import StageStatus, now_iso, sha256_file
from .persistence import atomic_json
from .scan import ScanResult
from .job_control import process_identity
from .activity import active_workers


def _legacy_key(path: str, host: str) -> str:
    return hashlib.sha256(json.dumps([os.path.normcase(str(Path(path).resolve())), host],
                                    ensure_ascii=False).encode()).hexdigest()


def adopt_legacy(case_dir: Path, config) -> None:
    """Index provenance from an older lake once, without rewriting its rows."""
    import duckdb

    case_dir = Path(case_dir).resolve()
    meta = read_metadata(case_dir)
    if "catalog" in meta:
        return
    backend = get_storage_backend(config)
    files = catalog_files(case_dir, backend, meta)
    if not files:
        return
    ledger = {}
    con = duckdb.connect()
    try:
        backend.configure_duckdb(con)
        con.execute("SET memory_limit='512MB'")
        con.execute("SET threads=2")
        for paths in files.values():
            relation = con.read_parquet([duckdb_path(path) for path in paths],
                                        hive_partitioning=True, union_by_name=True)
            if not {"source_path", "host", "file_sha256"}.issubset(relation.columns):
                raise ValueError("legacy lake lacks provenance columns; open it for analysis or import into a new Case")
            relation.create_view("_legacy", replace=True)
            rows = con.execute("SELECT source_path, host, file_sha256, count(*) FROM _legacy "
                               "GROUP BY source_path, host, file_sha256").fetchall()
            for path, host, digest, count in rows:
                if path is None or host is None or not digest:
                    continue
                ledger.setdefault(_legacy_key(path, host), []).append(
                    {"sha256": digest, "record_count": count, "status": "legacy_unknown",
                     "transaction_id": None, "source_path": path, "host": host})
    finally:
        con.close()
    with get_case_lock(case_dir, config) as lock:
        latest = read_metadata(case_dir)
        if "catalog" in latest:
            return
        if latest != meta or catalog_files(case_dir, backend, latest) != files:
            raise RuntimeError("legacy case changed during adoption; retry after the other import finishes")
        latest.update(catalog_version=1, catalog=encode_catalog(case_dir, files), legacy_ledger=ledger,
                      catalog_storage=catalog_storage_identity(backend))
        lock.assert_owned()
        atomic_json(case_dir / "case.json", latest)

INGEST_CONTRACT_VERSION = 2
WORKSPACE_DIR = ".ingest"


def storage_identity(config) -> list:
    endpoint = config.s3_endpoint_url
    if endpoint:
        parsed = urlsplit(endpoint)
        endpoint = [parsed.scheme, parsed.hostname, parsed.port, parsed.path]
    return [config.storage_backend, config.s3_bucket, endpoint, config.s3_region]


def catalog_storage_identity(backend) -> list:
    config = getattr(backend, "cluster_config", None)
    return storage_identity(config) if config is not None else ["local"]


def validate_outputs(files: dict[str, list[str]], backend, expected: dict[str, int]) -> None:
    """Check physical footer counts before visibility; flush local output files."""
    import duckdb

    actual = {}
    with duckdb.connect() as con:
        backend.configure_duckdb(con)
        con.execute("SET memory_limit='512MB'")
        con.execute("SET threads=2")
        for table, paths in files.items():
            actual[table] = int(con.execute("SELECT sum(num_rows) FROM parquet_file_metadata(?)",
                                           [[duckdb_path(path) for path in paths]]).fetchone()[0] or 0)
            for path in paths:
                if not path.startswith("s3://"):
                    with open(duckdb_path(path), "r+b") as stream:
                        os.fsync(stream.fileno())
    if {k: v for k, v in actual.items() if v} != {k: v for k, v in expected.items() if v}:
        raise RuntimeError(f"physical Parquet count mismatch: expected={expected}, actual={actual}; output not committed")


def read_metadata(case_dir: Path) -> dict:
    path = Path(case_dir) / "case.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def catalog_files(case_dir: Path, backend, meta: dict | None = None) -> dict[str, list[str]]:
    """Resolve a committed snapshot, falling back to a legacy physical lake."""
    case_dir = Path(case_dir).resolve()
    meta = read_metadata(case_dir) if meta is None else meta
    if "catalog" in meta:
        if meta.get("catalog_version") != 1:
            raise ValueError("unsupported case catalog version")
        if meta.get("catalog_storage", catalog_storage_identity(backend)) != catalog_storage_identity(backend):
            raise ValueError("storage configuration differs from the committed case catalog")
        result = {}
        for table, paths in meta["catalog"].items():
            resolved = []
            for value in paths:
                if value.startswith("s3://"):
                    backend._key(value)  # validate the configured bucket
                    resolved.append(value)
                else:
                    path = (case_dir / value).resolve()
                    if not path.is_relative_to(case_dir):
                        raise ValueError("case catalog path escapes the case directory")
                    resolved.append(str(path))
            if resolved:
                result[table] = resolved
        return result
    lake = backend.lake_location(case_dir)
    return {table: files for table in backend.table_dirs(lake)
            if (files := backend.list_parquet(backend.join(lake, table)))}


def encode_catalog(case_dir: Path, files: dict[str, list[str]]) -> dict[str, list[str]]:
    root = Path(case_dir).resolve()
    return {table: [p if p.startswith("s3://") else Path(p).resolve().relative_to(root).as_posix()
                    for p in paths] for table, paths in files.items() if paths}


def _source_identity(source, keep_raw: bool) -> dict:
    is_evtx = not hasattr(source, "kind")
    return {"path": os.path.normcase(str(source.path.resolve())), "host": source.host,
            "kind": "evtx" if is_evtx else source.kind,
            "ansi_codec": (getattr(source, "ansi_codec", None) or "windows-1252") if is_evtx else None,
            "keep_raw": bool(keep_raw) if is_evtx else False,
            "contract": INGEST_CONTRACT_VERSION}


def _identity_key(identity: dict) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def filter_committed(scan: ScanResult, meta: dict, keep_raw: bool) -> tuple[ScanResult, list[dict]]:
    """Hash only previously seen identities; the first import keeps one hash pass."""
    ledger = meta.get("source_ledger", {})
    skipped = []

    def keep(source):
        if hasattr(source, "kind") and source.kind is None:
            return True
        identity = _source_identity(source, keep_raw)
        candidates = list(ledger.get(_identity_key(identity), []))
        if (hasattr(source, "kind") or not keep_raw) and getattr(source, "ansi_codec", None) in (None, "windows-1252"):
            candidates.extend(meta.get("legacy_ledger", {}).get(_legacy_key(str(source.path), source.host), []))
        if not candidates:
            return True
        before = source.path.stat()
        digest = sha256_file(source.path)
        after = source.path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise OSError(f"source changed while verifying prior import: {source.path}")
        for previous in candidates:
            if previous["sha256"] == digest:
                skipped.append({**previous, "source_path": str(source.path), "host": source.host})
                return False
        return True

    return ScanResult([f for f in scan.evtx_files if keep(f)],
                      [f for f in scan.aux_files if keep(f)]), skipped


def _validate_removal(root: Path, target: Path, *, deep: bool = True) -> None:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(target))
    if not target.is_relative_to(root) or not target.resolve().is_relative_to(root.resolve()) or target == root:
        raise ValueError(f"refusing cleanup outside owned workspace: {target}")
    # Check every ancestor before resolving it away, including the owned root.
    for current in [root, *target.relative_to(root).parents]:
        if not current.is_absolute():
            current = root / current
        info = Path(duckdb_path(current)).lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"refusing cleanup through a link or reparse point: {current}")
    pending = [target]
    while pending:
        current = pending.pop()
        info = Path(duckdb_path(current)).lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"refusing cleanup of a link or reparse point: {current}")
        if deep and stat.S_ISDIR(info.st_mode):
            pending.extend(current / child.name for child in Path(duckdb_path(current)).iterdir())


class IngestTransaction:
    def __init__(self, case_dir: Path, config, scan: ScanResult, keep_raw: bool = False):
        self.case_dir = Path(case_dir).resolve()
        self.config = config
        self.backend = get_storage_backend(config)
        self.scan = scan
        self.keep_raw = keep_raw
        self.id = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        workspace_root = self.case_dir / WORKSPACE_DIR
        workspace_root.mkdir(parents=True, exist_ok=True)
        _validate_removal(self.case_dir, workspace_root, deep=False)
        self.workspace = workspace_root / self.id
        self.workspace.mkdir(parents=True)
        self._lock = LocalCaseLock(self.workspace)
        self.committed = False
        self.state = {"transaction_id": self.id, "phase": "running", "started_at": now_iso(),
                      **process_identity(),
                      "sources": [_source_identity(f, keep_raw) for f in [*scan.evtx_files, *scan.aux_files]],
                      "storage_backend": config.storage_backend,
                      "storage_identity": storage_identity(config)}

    def __enter__(self):
        self._lock.__enter__()
        try:
            atomic_json(self.workspace / "state.json", self.state)
        except BaseException:
            self._lock.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if not self.committed:
                self.state.update(phase="failed", error=str(exc or "batch was not committed"), finished_at=now_iso())
                try:
                    atomic_json(self.workspace / "state.json", self.state)
                except OSError:
                    pass  # leave the last durable state; the lock still releases
        finally:
            self._lock.__exit__(exc_type, exc, tb)

    def commit(self, report, run: dict) -> None:
        output = catalog_files(self.workspace, self.backend)
        validate_outputs(output, self.backend, {"events": report.records_flattened, **report.aux.rows_written})
        by_source = {(str(f.path.resolve()), f.host, getattr(f, "ansi_codec", None) or "windows-1252"): f
                     for f in [*self.scan.evtx_files, *self.scan.aux_files]}
        entries = []
        staged = [*report.staged_files, *report.aux.staged_files]
        for result in staged:
            if result.status not in (StageStatus.OK, StageStatus.PARTIAL) or not result.file_sha256:
                continue
            source = by_source.get((str(Path(result.source_path).resolve()), result.host,
                                    getattr(result, "ansi_codec", None) or "windows-1252"))
            if source is None:
                raise ValueError("staged source is absent from the discovery snapshot")
            identity = _source_identity(source, self.keep_raw)
            entry = {"identity": identity, "sha256": result.file_sha256, "status": result.status,
                     "record_count": result.record_count, "transaction_id": self.id}
            entries.append((_identity_key(identity), entry))
        # Preserve detailed source outcomes before publishing. The single
        # case.json replacement commits both files and their import ledger.
        atomic_json(self.workspace / "report.json", dataclasses.asdict(report))
        with get_case_lock(self.case_dir, self.config) as lock:
            meta = read_metadata(self.case_dir)
            ledger = meta.setdefault("source_ledger", {})
            for key, entry in entries:
                if any(old["sha256"] == entry["sha256"] for old in ledger.get(key, [])):
                    raise RuntimeError("another ingest committed the same source; retry to reuse its committed result")
            files = catalog_files(self.case_dir, self.backend, meta)
            for table, paths in output.items():
                files.setdefault(table, []).extend(paths)
            for key, entry in entries:
                ledger.setdefault(key, []).append(entry)
            meta.update(catalog_version=1, catalog=encode_catalog(self.case_dir, files),
                        catalog_storage=catalog_storage_identity(self.backend))
            meta.setdefault("ingest_runs", []).append({**run, "transaction_id": self.id})
            hosts = set(meta.get("hosts", []))
            hosts.update(f.host for f in staged if f.record_count)
            for paths in files.values():
                for path in paths:
                    hosts.update(unquote(p[5:]) for p in path.replace("\\", "/").split("/") if p.startswith("host="))
            meta["hosts"] = sorted(hosts)
            lock.assert_owned()
            atomic_json(self.case_dir / "case.json", meta)
            self.committed = True
        self.state.update(phase="committed", finished_at=now_iso())
        try:
            atomic_json(self.workspace / "state.json", self.state)
        except OSError:
            pass  # case.json is authoritative even after a post-commit failure


def cleanup_uncommitted(case_dir: Path, config) -> list[str]:
    """Remove inactive uncommitted bulk output; retain state/report audit files."""
    case_dir = Path(case_dir).resolve()
    root = case_dir / WORKSPACE_DIR
    removed = []
    if not root.exists():
        return removed
    _validate_removal(case_dir, root, deep=False)
    with get_case_lock(case_dir, config):
        meta = read_metadata(case_dir)
        committed = {run.get("transaction_id") for run in [*meta.get("ingest_runs", []), *meta.get("maintenance_runs", [])]}
        for workspace in root.iterdir():
            if not workspace.is_dir() or workspace.name in committed:
                continue
            try:
                if not re.fullmatch(r"[A-Za-z0-9_-]{22}", workspace.name):
                    uuid.UUID(workspace.name)
                _validate_removal(root, workspace, deep=False)
                with LocalCaseLock(workspace, timeout=0):
                    state_path = workspace / "state.json"
                    if not state_path.exists():
                        continue
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    if state.get("hostname") != socket.gethostname():
                        continue  # do not infer remote coordinator liveness
                    activity = workspace / "activity"
                    activity.mkdir(exist_ok=True)
                    with LocalCaseLock(activity):
                        if active_workers(workspace):
                            continue
                        state.update(phase="cleaning")
                        atomic_json(state_path, state)
                    _validate_removal(root, workspace)
                    if state.get("storage_backend") == "s3":
                        if state.get("storage_identity") != storage_identity(config):
                            raise ValueError("cleanup storage configuration differs from the original ingest")
                        get_storage_backend(config).remove_tree(get_storage_backend(config).lake_location(workspace))
                    for child in workspace.iterdir():
                        if child.name in ("state.json", "report.json", ".case.lock", "activity"):
                            continue
                        _validate_removal(workspace, child)
                        if Path(duckdb_path(child)).is_dir():
                            shutil.rmtree(duckdb_path(child))
                        else:
                            Path(duckdb_path(child)).unlink()
                        removed.append(str(child))
                    state.update(phase="cleaned", cleaned_at=now_iso())
                    atomic_json(state_path, state)
            except TimeoutError:
                continue
    return removed
