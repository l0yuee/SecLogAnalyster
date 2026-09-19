"""Per-file staging worker for the non-EVTX log families -- runs in a
worker process (files are independent), dispatches on the classification
from discover_and_classify(), and reports parse exceptions as failed or
partially recovered files. I/O failures propagate so damaged staging is
never published as successful input.

Parsed rows are written to bounded NDJSON or Arrow staging shards rather
than returned in-memory -- so the
coordinator never has to hold every row of every file in a batch at once,
and only a small manifest object crosses the worker/coordinator boundary
(over IPC locally, or over the job queue in distributed mode).
"""

from __future__ import annotations

import hashlib
from contextlib import nullcontext
from pathlib import Path

from ..resources import IngestOptions
from ..staging import StagingWriter
from ..arrow_staging import ArrowStagingWriter
from ...textdecode import PreparedText, _verify_prepared, prepare_text, use_prepared_text

from .discovery import ClassifiedFile, sha256_file
from .manifest import AuxStagedFile, StageStatus, now_iso
from .native import NativeBackendUnavailable, NativeBatchError, select_native_parser, stage_native_batches
from .partitioning import PartitionCollector
from .schema import TABLES
from .parsers.auditd import parse_auditd_file
from .parsers.dblogs import (
    parse_mssql_file,
    parse_mysql_error_file,
    parse_mysql_general_file,
    parse_mysql_slow_file,
    parse_oracle_alert_file,
    parse_postgresql_file,
)
from .parsers.exchange import parse_exchange_csv
from .parsers.iis import parse_iis_file
from .parsers.journal import parse_journal_file
from .parsers.qcloud import (
    parse_qcloud_go_file,
    parse_qcloud_scanner_file,
    parse_qcloud_ydeyes_file,
    parse_qcloud_ydservice_file,
    stream_qcloud_go_file,
    stream_qcloud_scanner_file,
    stream_qcloud_ydeyes_file,
    stream_qcloud_ydservice_file,
)
from .parsers.registry import parse_registry_hive_file
from .parsers.scheduled_tasks import parse_task_xml
from .parsers.syslog import parse_syslog_file
from .parsers.webaccess import parse_web_access_file
from .parsers.weberror import parse_apache_error_file, parse_iis_httperr_file, parse_nginx_error_file, parse_tomcat_error_file
from .sniff import (
    KIND_AUDITD,
    KIND_EXCHANGE_GENERIC,
    KIND_EXCHANGE_MESSAGE_TRACKING,
    KIND_IIS,
    KIND_IIS_HTTPERR,
    KIND_JOURNAL_EXPORT,
    KIND_MSSQL,
    KIND_MYSQL_ERROR,
    KIND_MYSQL_GENERAL,
    KIND_MYSQL_SLOW,
    KIND_ORACLE_ALERT,
    KIND_POSTGRESQL,
    KIND_QCLOUD_GO,
    KIND_QCLOUD_SCANNER,
    KIND_QCLOUD_YDEYES,
    KIND_QCLOUD_YDSERVICE,
    KIND_REGISTRY_HIVE,
    KIND_SCHEDULED_TASK,
    KIND_SYSLOG,
    KIND_WEB_ACCESS,
    KIND_WEB_ERROR_APACHE,
    KIND_WEB_ERROR_NGINX,
    KIND_WEB_ERROR_TOMCAT,
    guess_web_log_type,
)


_QCLOUD_STREAM_PARSERS = {
    KIND_QCLOUD_YDSERVICE: stream_qcloud_ydservice_file,
    KIND_QCLOUD_GO: stream_qcloud_go_file,
    KIND_QCLOUD_SCANNER: stream_qcloud_scanner_file,
    KIND_QCLOUD_YDEYES: stream_qcloud_ydeyes_file,
}

# Keep small artifacts cheap; amortize IPC schemas/buffers over larger input.
AUTO_ARROW_MIN_BYTES = 16 * 1024 * 1024


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def _staging_path(cf: ClassifiedFile, staging_dir: Path, table: str) -> Path:
    host_dir = staging_dir / cf.host
    host_dir.mkdir(parents=True, exist_ok=True)
    return host_dir / f"{table}.{cf.path.stem}.{_short_hash(str(cf.path))}.ndjson.gz"


def stage_aux_file(
    cf: ClassifiedFile, staging_dir: Path, options: IngestOptions | None = None,
    *, prepared: PreparedText | None = None,
) -> AuxStagedFile:
    # Checked before hashing: an unrecognized file (PE/ELF binaries and
    # any other non-log content mixed into evidence, which sniff.py
    # already spent only a cheap 16KB peek on) is never staged, and its
    # hash is never surfaced anywhere -- AuxIngestReport.unknown_samples
    # reports source_path only (see orchestrator.py). Hashing it in full
    # first was pure wasted I/O/CPU, and the main cost of "some PE and
    # ELF executables" mixed into an evidence set: ELF binaries in
    # particular usually have no extension, so they aren't caught by
    # discovery.py's _SKIP_SUFFIXES the way .exe/.dll/.sys are.
    if cf.kind is None:
        return AuxStagedFile(
            source_path=str(cf.path),
            source_file=cf.path.name,
            host=cf.host,
            file_sha256="",
            size_bytes=cf.size_bytes,
            kind=None,
            table=None,
            status=StageStatus.UNKNOWN,
            record_count=0,
            error_count=0,
            error_message="content did not match any supported log format",
            staged_at=now_iso(),
            parser_backend="none",
        )

    if prepared is not None:
        if (cf.kind in (KIND_REGISTRY_HIVE, KIND_SCHEDULED_TASK)
                or prepared.path != cf.path.resolve()
                or prepared.utf16_requires_bom != (cf.kind in _QCLOUD_STREAM_PARSERS)):
            raise ValueError("prepared source does not match the parser's source and decoding policy")
        # A direct-output fallback must reuse the original hash/encoding and
        # reject source changes, never prepare and silently accept new bytes.
        _verify_prepared(prepared)
    try:
        if cf.kind not in (KIND_REGISTRY_HIVE, KIND_SCHEDULED_TASK):
            if prepared is None:
                prepared = prepare_text(cf.path, utf16_requires_bom=cf.kind in _QCLOUD_STREAM_PARSERS)
            file_sha256 = prepared.sha256
        else:
            file_sha256 = sha256_file(cf.path)
    except OSError as e:
        return AuxStagedFile(
            source_path=str(cf.path),
            source_file=cf.path.name,
            host=cf.host,
            file_sha256="",
            size_bytes=cf.size_bytes,
            kind=cf.kind,
            table=None,
            status=StageStatus.FAILED,
            record_count=0,
            error_count=0,
            error_message=f"could not read file: {e}",
            staged_at=now_iso(),
            parser_backend="none",
        )

    options = options or IngestOptions()
    table = _table_for_kind(cf.kind)
    staging_path = _staging_path(cf, staging_dir, table)
    use_arrow = options.staging_format == "arrow" or (
        options.staging_format == "auto" and cf.size_bytes >= AUTO_ARROW_MIN_BYTES
    )
    if use_arrow:
        staging_path = staging_path.with_name(staging_path.name.removesuffix(".ndjson.gz") + ".arrow")

    def make_writer():
        if use_arrow:
            return ArrowStagingWriter(staging_path, options.staging_chunk_bytes,
                                      [col for col, _ in TABLES[table]["columns"]])
        return StagingWriter(staging_path, options.staging_chunk_bytes)

    selection = select_native_parser(cf, prepared, options, arrow_staging=use_arrow)
    parser_backend = "native" if selection.module is not None else "python"
    backend_reason = selection.reason
    writer = make_writer()
    partitions = PartitionCollector(table)
    error_count = 0
    parse_error = None
    source_path, source_file = str(cf.path), cf.path.name

    def emit(row: dict) -> None:
        row["source_path"] = source_path
        row["source_file"] = source_file
        row["file_sha256"] = file_sha256
        writer.write(row)
        partitions.add(row)

    try:
        with writer, (use_prepared_text(prepared) if prepared else nullcontext()):
            if cf.kind == KIND_SCHEDULED_TASK and cf.size_bytes > 8 * 1024 * 1024:
                raise ValueError("Scheduled Task XML exceeds the 8 MiB document limit")
            if selection.module is not None:
                try:
                    error_count = stage_native_batches(selection.module, cf, prepared, writer, partitions)
                except selection.module.UnsupportedInputError as exc:
                    if isinstance(exc, (OSError, NativeBatchError)):
                        # A broken companion API may expose an overly broad
                        # exception class. It cannot reclassify fatal errors.
                        raise
                    if options.parser_backend == "native":
                        raise NativeBackendUnavailable(f"native parser cannot handle {cf.path}: {exc}") from exc
                    # A capability mismatch may occur late in a file. Discard
                    # every native shard before replaying the whole source;
                    # an accepted prefix must never be emitted twice.
                    writer.abort()
                    parser_backend = "python"
                    backend_reason = f"native compatibility fallback: {exc}"
                    writer = make_writer()
                    partitions = PartitionCollector(table)
                    with writer:
                        _, _, _, error_count = _parse(cf, emit=emit)
            else:
                _, _, _, error_count = _parse(cf, emit=emit)
    except (OSError, NativeBackendUnavailable, NativeBatchError):
        # A full disk / write failure is not a recoverable parse error. Do
        # not present potentially damaged staging shards as successful input.
        # __exit__ has closed the writer and discarded any incomplete shard.
        # Keep its failed state, accepted counts and completed-shard metadata;
        # abort() resets those only when deliberately replaying a whole source.
        for chunk in writer.chunks:
            Path(chunk.path).unlink(missing_ok=True)
        raise
    except Exception as exc:
        parse_error = f"parse error: {exc}"
        error_count += 1

    ok_count = writer.record_count
    if ok_count == 0:
        status = StageStatus.FAILED
    elif error_count > 0 or parse_error:
        status = StageStatus.PARTIAL
    else:
        status = StageStatus.OK

    ndjson_out = writer.chunks[0].path if writer.chunks else None

    return AuxStagedFile(
        source_path=str(cf.path),
        source_file=cf.path.name,
        host=cf.host,
        file_sha256=file_sha256,
        size_bytes=cf.size_bytes,
        kind=cf.kind,
        table=table,
        status=status,
        record_count=ok_count,
        error_count=error_count,
        error_message=parse_error or (f"{error_count} row(s) rejected (format mismatch)" if error_count else None),
        ndjson_path=ndjson_out,
        staged_at=now_iso(),
        chunks=writer.chunks,
        partition_rows=partitions.rows,
        parser_backend=parser_backend,
        backend_reason=backend_reason,
    )


def _table_for_kind(kind: str) -> str:
    if kind == KIND_SCHEDULED_TASK:
        return "scheduled_tasks"
    if kind in (KIND_IIS, KIND_WEB_ACCESS):
        return "web_logs"
    if kind == KIND_EXCHANGE_MESSAGE_TRACKING:
        return "exchange_message_tracking"
    if kind == KIND_EXCHANGE_GENERIC:
        return "exchange_logs"
    if kind in (KIND_WEB_ERROR_NGINX, KIND_WEB_ERROR_APACHE, KIND_WEB_ERROR_TOMCAT, KIND_IIS_HTTPERR):
        return "web_error_logs"
    if kind == KIND_SYSLOG:
        return "syslog"
    if kind == KIND_AUDITD:
        return "auditd_logs"
    if kind == KIND_JOURNAL_EXPORT:
        return "journal_logs"
    if kind in (KIND_MYSQL_ERROR, KIND_MYSQL_GENERAL, KIND_MYSQL_SLOW, KIND_POSTGRESQL, KIND_MSSQL, KIND_ORACLE_ALERT):
        return "db_logs"
    if kind in _QCLOUD_STREAM_PARSERS:
        return "qcloud_logs"
    if kind == KIND_REGISTRY_HIVE:
        return "registry"
    raise ValueError(f"no parser registered for kind {kind!r}")


def _parse(cf: ClassifiedFile, *, emit=None) -> tuple[list[dict], str, int, int]:
    if cf.kind == KIND_SCHEDULED_TASK:
        row = parse_task_xml(cf.path, cf.host)
        if emit is not None:
            emit(row)
            return [], "scheduled_tasks", 1, 0
        return [row], "scheduled_tasks", 1, 0
    if cf.kind in _QCLOUD_STREAM_PARSERS and emit is not None:
        ok, err = _QCLOUD_STREAM_PARSERS[cf.kind](cf.path, cf.host, emit)
        return [], "qcloud_logs", ok, err
    if cf.kind == KIND_IIS:
        rows, ok, err = parse_iis_file(cf.path, cf.host, emit=emit)
        return rows, "web_logs", ok, err
    if cf.kind == KIND_WEB_ACCESS:
        log_type = guess_web_log_type(cf.path)
        rows, ok, err = parse_web_access_file(cf.path, cf.host, log_type, emit=emit)
        return rows, "web_logs", ok, err
    if cf.kind in (KIND_EXCHANGE_MESSAGE_TRACKING, KIND_EXCHANGE_GENERIC):
        table, rows, ok, err = parse_exchange_csv(cf.path, cf.host, cf.kind, emit=emit)
        return rows, table, ok, err
    if cf.kind == KIND_WEB_ERROR_NGINX:
        rows, ok, err = parse_nginx_error_file(cf.path, cf.host, emit=emit)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_WEB_ERROR_APACHE:
        rows, ok, err = parse_apache_error_file(cf.path, cf.host, emit=emit)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_WEB_ERROR_TOMCAT:
        rows, ok, err = parse_tomcat_error_file(cf.path, cf.host, emit=emit)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_IIS_HTTPERR:
        rows, ok, err = parse_iis_httperr_file(cf.path, cf.host, emit=emit)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_SYSLOG:
        rows, ok, err = parse_syslog_file(cf.path, cf.host, emit=emit)
        return rows, "syslog", ok, err
    if cf.kind == KIND_AUDITD:
        rows, ok, err = parse_auditd_file(cf.path, cf.host, emit=emit)
        return rows, "auditd_logs", ok, err
    if cf.kind == KIND_JOURNAL_EXPORT:
        rows, ok, err = parse_journal_file(cf.path, cf.host, emit=emit)
        return rows, "journal_logs", ok, err
    if cf.kind == KIND_MYSQL_ERROR:
        rows, ok, err = parse_mysql_error_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MYSQL_GENERAL:
        rows, ok, err = parse_mysql_general_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MYSQL_SLOW:
        rows, ok, err = parse_mysql_slow_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_POSTGRESQL:
        rows, ok, err = parse_postgresql_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MSSQL:
        rows, ok, err = parse_mssql_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_ORACLE_ALERT:
        rows, ok, err = parse_oracle_alert_file(cf.path, cf.host, emit=emit)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_QCLOUD_YDSERVICE:
        rows, ok, err = parse_qcloud_ydservice_file(cf.path, cf.host)
        return rows, "qcloud_logs", ok, err
    if cf.kind == KIND_QCLOUD_GO:
        rows, ok, err = parse_qcloud_go_file(cf.path, cf.host)
        return rows, "qcloud_logs", ok, err
    if cf.kind == KIND_QCLOUD_SCANNER:
        rows, ok, err = parse_qcloud_scanner_file(cf.path, cf.host)
        return rows, "qcloud_logs", ok, err
    if cf.kind == KIND_QCLOUD_YDEYES:
        rows, ok, err = parse_qcloud_ydeyes_file(cf.path, cf.host)
        return rows, "qcloud_logs", ok, err
    if cf.kind == KIND_REGISTRY_HIVE:
        rows, ok, err = parse_registry_hive_file(cf.path, cf.host, emit=emit)
        return rows, "registry", ok, err
    raise ValueError(f"no parser registered for kind {cf.kind!r}")
