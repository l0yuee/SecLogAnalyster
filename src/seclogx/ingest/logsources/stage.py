"""Per-file staging worker for the non-EVTX log families -- runs in a
worker process (files are independent), dispatches on the classification
from discover_and_classify(), and never raises: any parse exception is
caught and reported as a failed file.
"""

from __future__ import annotations

from .discovery import ClassifiedFile, sha256_file
from .manifest import AuxStagedFile, StageStatus, now_iso
from .parsers.exchange import parse_exchange_csv
from .parsers.iis import parse_iis_file
from .parsers.scheduled_tasks import parse_task_xml
from .parsers.webaccess import parse_web_access_file
from .parsers.weberror import parse_apache_error_file, parse_iis_httperr_file, parse_nginx_error_file, parse_tomcat_error_file
from .sniff import (
    KIND_EXCHANGE_GENERIC,
    KIND_EXCHANGE_MESSAGE_TRACKING,
    KIND_IIS,
    KIND_IIS_HTTPERR,
    KIND_SCHEDULED_TASK,
    KIND_WEB_ACCESS,
    KIND_WEB_ERROR_APACHE,
    KIND_WEB_ERROR_NGINX,
    KIND_WEB_ERROR_TOMCAT,
    guess_web_log_type,
)


def stage_aux_file(cf: ClassifiedFile) -> AuxStagedFile:
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

    if cf.kind is None:
        return AuxStagedFile(
            source_path=str(cf.path),
            source_file=cf.path.name,
            host=cf.host,
            file_sha256=file_sha256,
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
        rows=rows,
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
    raise ValueError(f"no parser registered for kind {cf.kind!r}")
