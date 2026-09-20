"""Merge small local Parquet files behind the atomic case catalog boundary.

Old files remain available to readers of the previous snapshot. Reclamation
is a separate lease-aware operation; compaction itself never deletes input.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
import re

import pyarrow.parquet as pq

from ..distributed.config import ClusterConfig
from ..distributed.locking import get_case_lock
from ..distributed.storage import get_storage_backend
from ..query import CaseDB
from ..paths import duckdb_path
from .common import now_iso
from .persistence import atomic_json
from .resources import CONVERSION_LOCK, IngestOptions
from .scan import ScanResult
from .transactions import (
    IngestTransaction, catalog_files, catalog_storage_identity, encode_catalog, read_metadata, validate_outputs,
)

_SMALL_FILE_BYTES = 8 * 1024 * 1024
_GROUP_BYTES = 256 * 1024 * 1024
_AUTO_MIN_FILES = 128


@dataclass
class CompactionReport:
    status: str
    input_files: int = 0
    output_files: int = 0
    rows: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    elapsed_seconds: float = 0.0
    transaction_id: str | None = None
    reason: str | None = None

    def summary_text(self) -> str:
        if self.status == "skipped":
            return f"Compaction skipped: {self.reason}"
        return (f"Compaction: {self.input_files} files merged into {self.output_files}, "
                f"{self.rows} rows preserved; old files retained for active readers")


def _partition_parts(case_dir: Path, table: str, path: Path) -> tuple[str, ...]:
    parts = path.relative_to(case_dir).parts
    positions = [i for i in range(len(parts) - 1) if parts[i:i + 2] == ("lake", table)]
    if not positions:
        raise ValueError(f"unsupported catalog layout for compaction: {path}")
    partition = parts[positions[-1] + 2:-1]
    if any("=" not in segment for segment in partition):
        raise ValueError(f"unsupported partition layout for compaction: {path}")
    return partition


def _plan_groups(case_dir: Path, snapshot: dict[str, list[str]], automatic: bool):
    partitions: dict[tuple[str, tuple[str, ...]], list[tuple[str, int]]] = {}
    for table, paths in snapshot.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
            raise ValueError("invalid catalog table name")
        for value in paths:
            path = Path(value).resolve()
            if not path.is_relative_to(case_dir):
                raise ValueError("compaction input escapes the case directory")
            size = Path(duckdb_path(path)).stat().st_size
            if size >= _SMALL_FILE_BYTES:
                continue
            key = table, _partition_parts(case_dir, table, path)
            partitions.setdefault(key, []).append((str(path), size))
    groups = []
    for (table, partition), files in sorted(partitions.items()):
        if len(files) < (_AUTO_MIN_FILES if automatic else 2):
            continue
        batch: list[str] = []
        size = 0
        for path, file_size in sorted(files):
            if batch and size + file_size > _GROUP_BYTES:
                if len(batch) > 1:
                    groups.append((table, partition, batch))
                batch, size = [], 0
            batch.append(path)
            size += file_size
        if len(batch) > 1:
            groups.append((table, partition, batch))
    return groups


def _write_group(con, paths: list[str], destination: Path) -> int:
    Path(duckdb_path(destination.parent)).mkdir(parents=True, exist_ok=True)
    con.read_parquet([duckdb_path(path) for path in paths], hive_partitioning=True,
                     union_by_name=True).create_view("_compact_source", replace=True)
    schema_before = con.execute("DESCRIBE SELECT * FROM _compact_source").fetchall()
    expected = 0
    for path in paths:
        with pq.ParquetFile(duckdb_path(path)) as parquet:
            expected += parquet.metadata.num_rows
    target = duckdb_path(destination).replace("'", "''")
    count = con.execute(
        f"COPY _compact_source TO '{target}' "
        "(FORMAT PARQUET, COMPRESSION ZSTD, COMPRESSION_LEVEL 1, ROW_GROUP_SIZE 122880)"
    ).fetchone()[0]
    with pq.ParquetFile(duckdb_path(destination)) as parquet:
        written = parquet.metadata.num_rows
    con.read_parquet(duckdb_path(destination), hive_partitioning=True, union_by_name=True).create_view(
        "_compact_check", replace=True)
    schema_after = con.execute("DESCRIBE SELECT * FROM _compact_check").fetchall()
    if count != expected or written != expected:
        raise RuntimeError("compaction row count mismatch; output was not committed")
    if schema_before != schema_after:
        raise RuntimeError("compaction changed a column's type or metadata; output was not committed")
    return int(count)


def compact_case(case_dir: Path, cluster_config: ClusterConfig | None = None, *,
                 automatic: bool = False) -> CompactionReport:
    """Merge small files using one 2 GB/two-thread DuckDB connection.

    Automatic maintenance requires 128 small files in one table/partition.
    An explicit call merges groups of at least two files. Both use groups
    up to 256 MiB of compressed input. S3 is not supported here.
    """
    started = perf_counter()
    case_dir = Path(case_dir).resolve()
    config = cluster_config or ClusterConfig.from_env()
    if config.is_s3:
        if automatic:
            return CompactionReport("skipped", reason="automatic compaction supports local storage only")
        raise NotImplementedError("compaction currently supports local storage only")
    backend = get_storage_backend(config)
    # CaseDB holds a reader lease so concurrent maintenance cannot reclaim
    # this exact snapshot while its replacement is being written.
    with CaseDB(case_dir, cluster_config=config) as db:
        snapshot = db.parquet_files
        groups = _plan_groups(case_dir, snapshot, automatic)
        if not groups:
            return CompactionReport("skipped", reason="no eligible groups of small files",
                                    elapsed_seconds=perf_counter() - started)
        with IngestTransaction(case_dir, config, ScanResult([], [])) as tx:
            tx.state.update(kind="compaction", automatic=automatic)
            atomic_json(tx.workspace / "state.json", tx.state)
            report = CompactionReport("committed", transaction_id=tx.id)
            replacements: dict[str, list[str]] = {}
            expected_rows: dict[str, int] = {}
            retired: set[str] = set()
            signatures: dict[str, tuple[int, int]] = {}
            with CONVERSION_LOCK:
                IngestOptions().configure_connection(db.connection)
                db.connection.execute("SET temp_directory = ?", [duckdb_path(tx.workspace / "duckdb_tmp")])
                for index, (table, partition, paths) in enumerate(groups):
                    for path in paths:
                        info = Path(duckdb_path(path)).stat()
                        signatures[path] = (info.st_size, info.st_mtime_ns)
                        report.bytes_before += info.st_size
                    destination = tx.workspace.joinpath("lake", table, *partition, f"compact-{index}.parquet")
                    rows = _write_group(db.connection, paths, destination)
                    report.rows += rows
                    expected_rows[table] = expected_rows.get(table, 0) + rows
                    report.bytes_after += Path(duckdb_path(destination)).stat().st_size
                    report.input_files += len(paths)
                    report.output_files += 1
                    replacements.setdefault(table, []).append(str(destination))
                    retired.update(paths)
            for path, expected in signatures.items():
                info = Path(duckdb_path(path)).stat()
                if (info.st_size, info.st_mtime_ns) != expected:
                    raise RuntimeError("compaction input changed; output was not committed")
            # Validate and fsync only our newly written, unpublished files
            # before case.json can make them visible. The shared helper uses
            # r+b handles, which Windows requires for FlushFileBuffers.
            validate_outputs(replacements, backend, expected_rows)
            with get_case_lock(case_dir, config) as lock:
                meta = read_metadata(case_dir)
                if catalog_files(case_dir, backend, meta) != snapshot:
                    raise RuntimeError("case catalog changed during compaction; retry maintenance")
                updated = {table: [path for path in paths if path not in retired]
                           for table, paths in snapshot.items()}
                for table, paths in replacements.items():
                    updated.setdefault(table, []).extend(paths)
                finished = now_iso()
                report.elapsed_seconds = perf_counter() - started
                if "catalog" not in meta:
                    # Compaction may be an analyst's first action on an old
                    # Case. Publishing a catalog must not bypass the source
                    # ledger adoption required before a subsequent ingest.
                    meta["legacy_provenance_pending"] = True
                    meta["catalog_storage"] = catalog_storage_identity(backend)
                meta.update(catalog_version=1, catalog=encode_catalog(case_dir, updated))
                meta.setdefault("maintenance_runs", []).append({**asdict(report), "kind": "compaction",
                    "automatic": automatic, "started_at": tx.state["started_at"], "finished_at": finished})
                meta.setdefault("retired_files", []).extend(
                    {"path": Path(path).relative_to(case_dir).as_posix(),
                     "retired_at": finished, "maintenance_id": tx.id} for path in sorted(retired))
                lock.assert_owned()
                atomic_json(case_dir / "case.json", meta)
                tx.committed = True
            tx.state.update(phase="committed", finished_at=finished)
            try:
                atomic_json(tx.workspace / "state.json", tx.state)
            except OSError:
                pass  # case.json is the authoritative commit record
            return report
