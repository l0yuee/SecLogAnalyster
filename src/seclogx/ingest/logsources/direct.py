"""Optional local native Arrow-to-Parquet conversion without IPC staging.

The coordinator owns this single conversion lane. Native buffers never cross
a process boundary, and the ordinary conversion lock covers the connection's
entire lifetime. A source remains private until parsing, COPY and source-handle
verification have all completed.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import shutil
import tempfile
from urllib.parse import quote
import uuid

import duckdb
import pyarrow as pa
import pyarrow.compute as pc

from ...distributed.storage import LocalStorageBackend, ensure_hive_partition_dirs
from ...textdecode import PreparedText, _verify_prepared, prepare_text
from ..arrow_staging import ArrowStagingWriter
from ..resources import CONVERSION_LOCK, IngestOptions
from .discovery import ClassifiedFile
from .flatten import build_select_query
from .manifest import AuxStagedFile, StageStatus, now_iso
from .native import (
    NativeBackendUnavailable,
    NativeBatchError,
    native_reader,
    read_native_error_count,
    select_native_parser,
)
from .schema import TABLES
from .sniff import KIND_IIS, guess_web_log_type


@dataclass(frozen=True)
class DirectResult:
    """A published source, or a request to replay the same prepared source."""

    staged_file: AuxStagedFile | None
    prepared: PreparedText | None
    parquet_path: str | None = None
    rows_written: int = 0
    fallback_reason: str | None = None


@dataclass
class _StreamState:
    accepted_rows: int = 0
    finished: bool = False
    error_count: int = 0
    parse_error: str | None = None
    terminal_error: BaseException | None = None
    unsupported: BaseException | None = None


def _is_unsupported(exc: BaseException, module) -> bool:
    # An optional component cannot redefine fatal storage/protocol errors by
    # exposing an excessively broad UnsupportedInputError class.
    return not isinstance(exc, (OSError, NativeBatchError)) and isinstance(exc, module.UnsupportedInputError)


def _native_batches(reader, module, validator, cf, log_type, state):
    while True:
        try:
            native_batch = reader.next_batch()
        except BaseException as exc:
            if _is_unsupported(exc, module):
                state.unsupported = state.terminal_error = exc
                raise
            if isinstance(exc, ValueError) and not isinstance(exc, (OSError, NativeBatchError)):
                # Only parsing itself may end a source with a recovered prefix.
                # Batch import/validation, COPY and close errors never enter
                # this branch. Match the existing staging parse-error count.
                state.parse_error = f"parse error: {exc}"
                state.error_count = 1
                state.finished = True
                return
            state.terminal_error = exc
            raise
        if native_batch is None:
            try:
                state.error_count = read_native_error_count(reader)
            except BaseException as exc:
                state.terminal_error = exc
                raise
            state.finished = True
            return
        try:
            batch = pa.record_batch(native_batch)
            sizes = pa.array(native_batch.encoded_record_sizes)
            validator._validate_batch(batch, sizes)
            if batch.num_rows:
                # Publishing directly into a fixed Hive partition requires a
                # checked invariant, not merely the companion's promise.
                for column, expected in (("host", cf.host), ("log_type", log_type)):
                    values = batch.column(batch.schema.get_field_index(column))
                    if values.null_count or not pc.all(pc.equal(values, expected)).as_py():
                        raise ValueError(f"native batch changed its fixed {column} partition")
        except BaseException as exc:
            if isinstance(exc, (OSError, KeyboardInterrupt, SystemExit)):
                state.terminal_error = exc
                raise
            error = NativeBatchError(f"invalid native batch for {cf.path}: {exc}")
            state.terminal_error = error
            raise error from exc
        # Empty batches bound work on invalid/comment-only source ranges.
        # They are progress boundaries, not end-of-stream sentinels.
        if batch.num_rows:
            state.accepted_rows += batch.num_rows
            yield batch


def _remove_private(path: Path, private_root: Path) -> None:
    """Remove only the newly-created, direct child of our private root."""
    if path.resolve().parent != private_root.resolve() or path.is_symlink():
        raise OSError(f"refusing to clean an unexpected private output path: {path}")
    shutil.rmtree(path)


@contextmanager
def _direct_reader(module, cf, prepared, validator, state):
    entered = False
    try:
        with native_reader(module, cf, prepared, validator) as reader:
            entered = True
            yield reader
    except BaseException as exc:
        # Only a failure to open the parser can request this fallback. SQL or
        # close errors outside that boundary must remain fatal.
        if not entered and _is_unsupported(exc, module):
            state.unsupported = exc
        raise


def _copy_source(module, cf, prepared, validator, private_path, options, batch_id, ingested_at, log_type, state):
    with CONVERSION_LOCK, duckdb.connect() as con:
        options.configure_connection(con)
        # Any DuckDB spill also belongs to this source's private lifetime.
        temporary = str(private_path.parent / "duckdb_tmp").replace("'", "''")
        con.execute(f"SET temp_directory = '{temporary}'")
        with _direct_reader(module, cf, prepared, validator, state) as reader:
            with ExitStack() as inputs:
                batches = _native_batches(reader, module, validator, cf, log_type, state)
                inputs.callback(batches.close)
                arrow = pa.RecordBatchReader.from_batches(validator.schema, batches)
                inputs.callback(arrow.close)
                con.register("direct_arrow", arrow)
                inputs.callback(con.unregister, "direct_arrow")
                normalized = build_select_query("web_logs", batch_id, ingested_at,
                                                "FROM direct_arrow AS raw")
                # Existing partitioned COPY omits partition columns from
                # physical files; Hive directories restore them.
                query = f"SELECT * EXCLUDE (host, log_type) FROM ({normalized})"
                destination = str(private_path).replace("'", "''")
                try:
                    result = con.execute(
                        f"COPY ({query}) TO '{destination}' "
                        "(FORMAT PARQUET, COMPRESSION ZSTD, COMPRESSION_LEVEL 1)"
                    ).fetchone()
                    copied_rows = int(result[0])
                except BaseException as exc:
                    # DuckDB can wrap Arrow callback errors. Restore the
                    # original classification before unwinding resources, so
                    # a subsequent cleanup failure retains both causes.
                    if state.terminal_error is not None and state.terminal_error is not exc:
                        raise state.terminal_error from exc
                    raise
                if not state.finished or state.terminal_error is not None:
                    raise NativeBatchError(f"native stream did not finish cleanly for {cf.path}")
                if copied_rows != state.accepted_rows:
                    raise NativeBatchError(f"native COPY row count differs for {cf.path}")
        # The native_reader exit closes both native/source handles and
        # verifies the prepared identity before the connection closes.
    return copied_rows


def direct_web_file(
    cf: ClassifiedFile,
    case_dir: Path,
    batch_id: str,
    ingested_at: datetime,
    options: IngestOptions,
    *,
    prepared: PreparedText | None = None,
) -> DirectResult:
    """Convert one eligible native source locally, publishing only on success.

    The caller checks local execution/storage and keep_staging=False, and
    performs any Python replay. A fallback returns the identical PreparedText;
    re-preparing would permit unnoticed replacement of the evidence source.
    """
    if prepared is None:
        try:
            prepared = prepare_text(cf.path)
        except OSError as exc:
            failed = AuxStagedFile(
                source_path=str(cf.path), source_file=cf.path.name, host=cf.host,
                file_sha256="", size_bytes=cf.size_bytes, kind=cf.kind, table=None,
                status=StageStatus.FAILED, record_count=0, error_count=0,
                error_message=f"could not read file: {exc}", staged_at=now_iso(),
                parser_backend="none", output_format="parquet",
            )
            return DirectResult(failed, None)
    elif prepared.path != cf.path.resolve() or prepared.utf16_requires_bom:
        raise ValueError("prepared source must match the direct source path and decoding policy")
    _verify_prepared(prepared)
    selection = select_native_parser(cf, prepared, options, arrow_staging=True)
    if selection.module is None:
        return DirectResult(None, prepared, fallback_reason=selection.reason or "Python parser selected")

    module = selection.module
    log_type = "iis" if cf.kind == KIND_IIS else guess_web_log_type(cf.path)
    private_root = Path(case_dir) / "_ingest_private"
    private_root.mkdir(parents=True, exist_ok=True)
    private_dir = Path(tempfile.mkdtemp(prefix="web-", dir=private_root))
    private_path = private_dir / "part.parquet"
    state = _StreamState()
    try:
        # This object only supplies the already-reviewed schema/limits/validator.
        # Its lazy output stream is never opened; write/write_batch are not called.
        validator = ArrowStagingWriter(private_dir / "unused.arrow", options.staging_chunk_bytes,
                                       [name for name, _ in TABLES["web_logs"]["columns"]])
        try:
            copied_rows = _copy_source(module, cf, prepared, validator, private_path, options,
                                       batch_id, ingested_at, log_type, state)
        except BaseException as exc:
            if state.unsupported is exc:
                if options.parser_backend == "native":
                    raise NativeBackendUnavailable(f"native parser cannot handle {cf.path}: {exc}") from exc
                # Cleanup must finish before the caller may replay a source.
                _remove_private(private_dir, private_root)
                return DirectResult(None, prepared, fallback_reason=f"native compatibility fallback: {exc}")
            raise

        status = (StageStatus.FAILED if copied_rows == 0 else
                  StageStatus.PARTIAL if state.error_count or state.parse_error else StageStatus.OK)
        backend = LocalStorageBackend()
        lake = backend.table_location(Path(case_dir), "web_logs")
        published = None
        if copied_rows:
            partition = (cf.host, log_type)
            ensure_hive_partition_dirs(backend, lake, ("host", "log_type"), [partition])
            parts = [f"{name}={quote(value, safe='')}" for name, value in zip(("host", "log_type"), partition)]
            published = Path(backend.join(lake, *parts, f"{uuid.uuid4().hex}.parquet"))
            if published.exists():
                raise FileExistsError(f"direct output already exists: {published}")
        manifest = AuxStagedFile(
            source_path=str(cf.path), source_file=cf.path.name, host=cf.host,
            file_sha256=prepared.sha256, size_bytes=cf.size_bytes, kind=cf.kind, table="web_logs",
            status=status, record_count=copied_rows, error_count=state.error_count,
            error_message=state.parse_error or (
                f"{state.error_count} row(s) rejected (format mismatch)" if state.error_count else None),
            staged_at=now_iso(), partition_rows=[(cf.host, log_type)] if copied_rows else [],
            parser_backend="native", output_format="parquet",
            parquet_paths=[str(published)] if published else [],
        )
        if published is None:
            _remove_private(private_dir, private_root)
            return DirectResult(manifest, prepared)

        # Close completed above. Remove only our temporary spill directory;
        # unexpected extra files prevent publishing an incomplete operation.
        spill = private_dir / "duckdb_tmp"
        if spill.exists():
            if spill.resolve().parent != private_dir.resolve() or spill.is_symlink():
                raise OSError(f"unexpected DuckDB spill path: {spill}")
            shutil.rmtree(spill)
        if set(private_dir.iterdir()) != {private_path}:
            raise OSError(f"unexpected files remain in private output: {private_dir}")
        # Recheck immediately before publication, after footer/handle closure.
        _verify_prepared(prepared)
        if os.name == "nt":
            # Windows rename fails atomically if the destination exists.
            private_path.rename(published)
        else:
            # POSIX rename may replace an existing destination. Creating a
            # hard link is an atomic no-clobber publication on a local volume;
            # unsupported filesystems fail rather than switching to a copy.
            os.link(private_path, published)
    except BaseException:
        if private_dir.exists():
            _remove_private(private_dir, private_root)
        raise

    # Publication is complete. Removing the POSIX private link or the empty
    # scratch directory is housekeeping; failure cannot make an already-visible
    # successful source disappear from the report.
    if os.name != "nt":
        try:
            private_path.unlink()
        except OSError:
            pass
    try:
        private_dir.rmdir()
    except OSError:
        pass
    return DirectResult(manifest, prepared, str(published), copied_rows)
