"""Per-file staging worker for the non-EVTX log families -- runs in a
worker process (files are independent), dispatches on the classification
from discover_and_classify(), and never raises: any parse exception is
caught and reported as a failed file.

Parsed rows are written straight to a per-file NDJSON staging file (same
pattern as `ingest/evtx/stage.py`) rather than returned in-memory -- so the
coordinator never has to hold every row of every file in a batch at once,
and only a small manifest object crosses the worker/coordinator boundary
(over IPC locally, or over the job queue in distributed mode).
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from .discovery import ClassifiedFile, sha256_file
from .manifest import AuxStagedFile, StageStatus, now_iso
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
    KIND_SCHEDULED_TASK,
    KIND_SYSLOG,
    KIND_WEB_ACCESS,
    KIND_WEB_ERROR_APACHE,
    KIND_WEB_ERROR_NGINX,
    KIND_WEB_ERROR_TOMCAT,
    guess_web_log_type,
)


# See ingest/evtx/stage.py for why staged NDJSON is gzipped and why
# level 1 -- same tradeoff, same DuckDB-side transparency on read.
_GZIP_LEVEL = 1


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def stage_aux_file(cf: ClassifiedFile, staging_dir: Path) -> AuxStagedFile:
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
        )

    try:
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
        )

    try:
        rows, table, ok_count, error_count = _parse(cf)
    except Exception as e:  # noqa: BLE001 -- never let one bad file abort the ingest run
        return AuxStagedFile(
            source_path=str(cf.path),
            source_file=cf.path.name,
            host=cf.host,
            file_sha256=file_sha256,
            size_bytes=cf.size_bytes,
            kind=cf.kind,
            table=None,
            status=StageStatus.FAILED,
            record_count=0,
            error_count=0,
            error_message=f"parse error: {e}",
            staged_at=now_iso(),
        )

    for row in rows:
        row["source_path"] = str(cf.path)
        row["source_file"] = cf.path.name
        row["file_sha256"] = file_sha256

    if ok_count == 0:
        status = StageStatus.FAILED
    elif error_count > 0:
        status = StageStatus.PARTIAL
    else:
        status = StageStatus.OK

    ndjson_out: str | None = None
    if rows:
        host_dir = staging_dir / cf.host
        host_dir.mkdir(parents=True, exist_ok=True)
        # Hash suffix avoids collisions when files with the same basename
        # are discovered under the same host from different acquisition
        # paths (same scheme as ingest/evtx/stage.py).
        ndjson_path = host_dir / f"{table}.{cf.path.stem}.{_short_hash(str(cf.path))}.ndjson.gz"
        with gzip.open(ndjson_path, "wt", compresslevel=_GZIP_LEVEL) as out:
            for row in rows:
                out.write(json.dumps(row, default=str) + "\n")
        ndjson_out = str(ndjson_path)

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
        error_message=(f"{error_count} row(s) rejected (format mismatch)" if error_count else None),
        ndjson_path=ndjson_out,
        staged_at=now_iso(),
    )


def _parse(cf: ClassifiedFile) -> tuple[list[dict], str, int, int]:
    if cf.kind == KIND_SCHEDULED_TASK:
        row = parse_task_xml(cf.path, cf.host)
        return [row], "scheduled_tasks", 1, 0
    if cf.kind == KIND_IIS:
        rows, ok, err = parse_iis_file(cf.path, cf.host)
        return rows, "web_logs", ok, err
    if cf.kind == KIND_WEB_ACCESS:
        log_type = guess_web_log_type(cf.path)
        rows, ok, err = parse_web_access_file(cf.path, cf.host, log_type)
        return rows, "web_logs", ok, err
    if cf.kind in (KIND_EXCHANGE_MESSAGE_TRACKING, KIND_EXCHANGE_GENERIC):
        table, rows, ok, err = parse_exchange_csv(cf.path, cf.host, cf.kind)
        return rows, table, ok, err
    if cf.kind == KIND_WEB_ERROR_NGINX:
        rows, ok, err = parse_nginx_error_file(cf.path, cf.host)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_WEB_ERROR_APACHE:
        rows, ok, err = parse_apache_error_file(cf.path, cf.host)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_WEB_ERROR_TOMCAT:
        rows, ok, err = parse_tomcat_error_file(cf.path, cf.host)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_IIS_HTTPERR:
        rows, ok, err = parse_iis_httperr_file(cf.path, cf.host)
        return rows, "web_error_logs", ok, err
    if cf.kind == KIND_SYSLOG:
        rows, ok, err = parse_syslog_file(cf.path, cf.host)
        return rows, "syslog", ok, err
    if cf.kind == KIND_AUDITD:
        rows, ok, err = parse_auditd_file(cf.path, cf.host)
        return rows, "auditd_logs", ok, err
    if cf.kind == KIND_JOURNAL_EXPORT:
        rows, ok, err = parse_journal_file(cf.path, cf.host)
        return rows, "journal_logs", ok, err
    if cf.kind == KIND_MYSQL_ERROR:
        rows, ok, err = parse_mysql_error_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MYSQL_GENERAL:
        rows, ok, err = parse_mysql_general_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MYSQL_SLOW:
        rows, ok, err = parse_mysql_slow_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_POSTGRESQL:
        rows, ok, err = parse_postgresql_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_MSSQL:
        rows, ok, err = parse_mssql_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    if cf.kind == KIND_ORACLE_ALERT:
        rows, ok, err = parse_oracle_alert_file(cf.path, cf.host)
        return rows, "db_logs", ok, err
    raise ValueError(f"no parser registered for kind {cf.kind!r}")
