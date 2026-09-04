"""Parse Tencent Cloud Host Security (YunJing / Tencent CWPP) logs.

The deployed Linux agent uses four line-oriented formats across its core
service, Go sub-components, Python scanners, and the YDEyes engine.  They
land in one ``qcloud_logs`` table with a ``log_type`` discriminator.  A
small set of stable security summaries is additionally normalized into
dedicated fields; the original message and full raw line are always kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path

_YDSERVICE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"(?P<pid>\d+) (?P<tid>\d+) (?P<level>[A-Za-z]+) "
    r"(?P<module>[^: ]+):(?P<line>\d+) (?P<message>.*)$"
)
_GO_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\[(?P<level>[^]]+)\]\[(?P<source>[^]:]+):(?P<line>\d+)\](?P<message>.*)$"
)
_SCANNER_RE = re.compile(
    r"^\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] "
    r"\[(?P<level>[^]]+)\] (?P<message>.*)$"
)
_YDEYES_RE = re.compile(r"^\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (?P<message>.*)$")

_LOGIN_SUMMARY_RE = re.compile(
    r"\blogin (?P<result>failed|success(?:ful)?)\s+user:(?P<user>\S+)\s+"
    r"ip:(?P<ip>\S+)\s+block:(?P<block>[01])\s+port:(?P<port>\d+)",
    re.IGNORECASE,
)
_SSH_RESULT_RE = re.compile(
    r"\b(?P<result>Accepted|Failed) (?:password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_PAM_FAILURE_RE = re.compile(r"\bauthentication failure;.*\brhost=(?P<ip>\S+).*\buser=(?P<user>\S+)")
_MALWARE_RE = re.compile(
    r"\breport mod:\s*(?P<report_mod>\d+)\s+pid:\s*(?P<pid>\d+)\s+"
    r"md5:\s*(?P<md5>[0-9a-fA-F]{32})\s+path:\s*(?P<path>.*?)\s+trace:\s*(?P<trace>\S+)"
)
_QUARA_RESULT_RE = re.compile(
    r"\bresult \{MD5:(?P<md5>[0-9a-fA-F]{32}) Path:(?P<path>.*?) "
    r"FileExist:(?P<file_exists>true|false) ProcExist:(?P<proc_exists>true|false)\}",
    re.IGNORECASE,
)
_EXECUTE_COMMAND_RE = re.compile(
    r"^Execute Command \(uid:\s*(?P<uid>\d+), gid:\s*(?P<gid>\d+)\):\s*(?P<command>.*)$"
)
_ACCOUNT_INFO_RE = re.compile(
    r"user_name is (?P<user>.*?), group_name is (?P<group>.*?), shell_path is (?P<shell>.*?)\n"
    r", canlogin is (?P<canlogin>[01]), privilege is (?P<privilege>\d+),\s+modify_type is (?P<modify_type>\d+)"
)
_LEADING_IP_RE = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+)(?:_\d+)?\s+")


def guess_qcloud_log_type(path: Path, default: str) -> str:
    """Best-effort component label from the deployed YunJing path/name."""
    name = path.name.lower()
    parent = path.parent.name.lower()
    if name.startswith("ydservice."):
        return "ydservice"
    if name.startswith("hids.log"):
        return "hids"
    if name.startswith("ydlive.log"):
        return "ydlive"
    if name.startswith("vul_scan.log"):
        return "vul_scan"
    if name.startswith("baseline_scan.log"):
        return "baseline_scan"
    if name.startswith("ydflame."):
        return "ydflame"
    if name.startswith("ydutils.log"):
        return "ydutils"
    if name.startswith("ydquarav2.log"):
        return "ydquarav2"
    if (name == "log.txt" and parent == "ydeyes") or "ydeyes" in name:
        return "ydeyes"
    return default


def _empty_row(host: str, log_type: str, raw_line: str) -> dict:
    return {
        "host": host,
        "log_type": log_type,
        "time_created": None,
        "severity": None,
        "module": None,
        "code_file": None,
        "source_line": None,
        "process_id": None,
        "thread_id": None,
        "event_type": None,
        "user_name": None,
        "source_ip": None,
        "destination_port": None,
        "blocked": None,
        "subject_process_id": None,
        "file_path": None,
        "file_md5": None,
        "trace_id": None,
        "message": None,
        "raw_line": raw_line,
        "extra": None,
    }


def _sparse_row(host: str, log_type: str, raw_line: str) -> dict:
    """Minimal row used by the staging hot path; flatten supplies NULLs."""
    return {"host": host, "log_type": log_type, "raw_line": raw_line}


def _timestamp(value: str) -> str:
    """Return DuckDB-friendly ISO text.

    The enclosing format regex has already validated every numeric field.
    ``datetime.strptime`` here used to dominate large-file profiles despite
    adding no useful validation, so conversion is deliberately a cheap,
    allocation-light separator replacement.
    """
    return f"{value[:10]}T{value[11:]}"


def _enrich(row: dict) -> None:
    """Extract stable, high-value fields without treating debug prose as a schema."""
    message = row["message"] or ""
    extra: dict[str, object] = {}

    # Most client chatter is routine health/debug output. Cheap substring
    # gates avoid running every security-event regex against every line.
    match = _LOGIN_SUMMARY_RE.search(message) if "login " in message and "user:" in message else None
    if match:
        row["event_type"] = "login_failure" if match.group("result").lower() == "failed" else "login_success"
        row["user_name"] = match.group("user")
        row["source_ip"] = match.group("ip")
        row["destination_port"] = int(match.group("port"))
        row["blocked"] = match.group("block") == "1"
    else:
        match = _SSH_RESULT_RE.search(message) if " from " in message and ("Accepted " in message or "Failed " in message) else None
        if match:
            row["event_type"] = "login_success" if match.group("result").lower() == "accepted" else "login_failure"
            row["user_name"] = match.group("user")
            row["source_ip"] = match.group("ip")
            row["destination_port"] = int(match.group("port"))
        else:
            match = _PAM_FAILURE_RE.search(message) if "authentication failure;" in message else None
            if match:
                row["event_type"] = "login_failure"
                row["user_name"] = match.group("user")
                row["source_ip"] = match.group("ip")

    match = _MALWARE_RE.search(message) if "report mod:" in message else None
    if match:
        row["event_type"] = "malware_detection"
        row["subject_process_id"] = int(match.group("pid"))
        row["file_md5"] = match.group("md5").lower()
        row["file_path"] = match.group("path")
        row["trace_id"] = match.group("trace")
        extra["report_mod"] = int(match.group("report_mod"))

    match = _QUARA_RESULT_RE.search(message) if "result {MD5:" in message else None
    if match:
        row["event_type"] = "malware_scan"
        row["file_md5"] = match.group("md5").lower()
        row["file_path"] = match.group("path")
        extra["file_exists"] = match.group("file_exists").lower() == "true"
        extra["process_exists"] = match.group("proc_exists").lower() == "true"

    match = _EXECUTE_COMMAND_RE.match(message) if message.startswith("Execute Command ") else None
    if match:
        row["event_type"] = "command_execution"
        extra.update(uid=int(match.group("uid")), gid=int(match.group("gid")), command=match.group("command"))

    match = _ACCOUNT_INFO_RE.search(message) if "user_name is " in message and "\n, canlogin is " in message else None
    if match:
        row["event_type"] = "account_inventory"
        row["user_name"] = match.group("user")
        extra.update(
            group_name=match.group("group"),
            shell_path=match.group("shell"),
            can_login=match.group("canlogin") == "1",
            privilege=int(match.group("privilege")),
            modify_type=int(match.group("modify_type")),
        )

    lowered = message.lower()
    if row.get("event_type") is None and ("blacklist" in lowered or "blackiplist" in lowered):
        row["event_type"] = "ip_blocklist"
        match = _LEADING_IP_RE.match(message)
        if match:
            row["source_ip"] = match.group("ip")

    if row.get("event_type") is None:
        module = (row.get("module") or "").lower()
        event_type = {
            "bruteforce": "brute_force",
            "filemonitor": "file_monitor",
            "crontab": "scheduled_task",
            "historyprocessmonitor": "command_history",
            "accountinfo": "account_inventory",
            "netflow": "network_flow",
        }.get(module)
        if event_type is not None:
            row["event_type"] = event_type

    if extra:
        row["extra"] = json.dumps(extra, ensure_ascii=False)


def _stream_encoding(path: Path) -> str:
    """Choose an encoding from a bounded prefix without loading the file."""
    with path.open("rb") as source:
        prefix = source.read(64 * 1024)
    if prefix.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        prefix.decode("utf-8-sig")
        return "utf-8-sig"
    except UnicodeError:
        try:
            prefix.decode("gb18030")
            return "gb18030"
        except UnicodeError:
            return "latin-1"


def _iter_qcloud_lines(path: Path) -> Iterator[str]:
    encoding = _stream_encoding(path)
    with path.open("r", encoding=encoding, errors="replace", newline="") as source:
        for line in source:
            yield line.rstrip("\r\n")


def _stream_parsed_rows(
    path: Path,
    pattern: re.Pattern[str],
    make_row: Callable[[re.Match[str], str], dict],
    emit: Callable[[dict], None],
) -> tuple[int, int]:
    """Parse with one-row look-behind and emit completed logical records.

    Holding one row is necessary because Tencent scanner/account records can
    continue on the next physical line. It also keeps memory independent of
    file size when staging multi-million-line logs.
    """
    pending: dict | None = None
    record_count = 0
    error_count = 0
    for line in _iter_qcloud_lines(path):
        if not line.strip():
            continue
        match = pattern.match(line)
        if match:
            if pending is not None:
                emit(pending)
                record_count += 1
            pending = make_row(match, line)
        elif pending is None:
            error_count += 1
        else:
            pending["message"] = f"{pending['message']}\n{line}"
            pending["raw_line"] = f"{pending['raw_line']}\n{line}"
            _enrich(pending)
    if pending is not None:
        emit(pending)
        record_count += 1
    return record_count, error_count


def stream_qcloud_ydservice_file(
    path: Path, host: str, emit: Callable[[dict], None]
) -> tuple[int, int]:
    log_type = guess_qcloud_log_type(path, "ydservice")

    def make_row(match: re.Match[str], line: str) -> dict:
        row = _sparse_row(host, log_type, line)
        row.update(
            time_created=_timestamp(match.group("time")),
            severity=match.group("level"),
            module=match.group("module"),
            source_line=int(match.group("line")),
            process_id=int(match.group("pid")),
            thread_id=int(match.group("tid")),
            message=match.group("message"),
        )
        _enrich(row)
        return row

    return _stream_parsed_rows(path, _YDSERVICE_RE, make_row, emit)


def stream_qcloud_go_file(path: Path, host: str, emit: Callable[[dict], None]) -> tuple[int, int]:
    log_type = guess_qcloud_log_type(path, "go_component")

    def make_row(match: re.Match[str], line: str) -> dict:
        code_file = match.group("source")
        row = _sparse_row(host, log_type, line)
        row.update(
            time_created=_timestamp(match.group("time")),
            severity=match.group("level"),
            module=code_file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].rsplit(".", 1)[0],
            code_file=code_file,
            source_line=int(match.group("line")),
            message=match.group("message"),
        )
        _enrich(row)
        return row

    return _stream_parsed_rows(path, _GO_RE, make_row, emit)


def stream_qcloud_scanner_file(
    path: Path, host: str, emit: Callable[[dict], None]
) -> tuple[int, int]:
    log_type = guess_qcloud_log_type(path, "scanner")

    def make_row(match: re.Match[str], line: str) -> dict:
        row = _sparse_row(host, log_type, line)
        row.update(
            time_created=_timestamp(match.group("time")),
            severity=match.group("level"),
            module=log_type,
            message=match.group("message"),
        )
        _enrich(row)
        return row

    return _stream_parsed_rows(path, _SCANNER_RE, make_row, emit)


def stream_qcloud_ydeyes_file(
    path: Path, host: str, emit: Callable[[dict], None]
) -> tuple[int, int]:
    log_type = guess_qcloud_log_type(path, "ydeyes")

    def make_row(match: re.Match[str], line: str) -> dict:
        row = _sparse_row(host, log_type, line)
        row.update(
            time_created=_timestamp(match.group("time")),
            module="YDEyes",
            message=match.group("message"),
        )
        _enrich(row)
        return row

    return _stream_parsed_rows(path, _YDEYES_RE, make_row, emit)


def _collect_rows(
    path: Path,
    host: str,
    stream_parser: Callable[[Path, str, Callable[[dict], None]], tuple[int, int]],
) -> tuple[list[dict], int, int]:
    """Compatibility adapter for callers that explicitly request a list."""
    rows: list[dict] = []

    def collect(row: dict) -> None:
        full_row = _empty_row(host, row["log_type"], row["raw_line"])
        full_row.update(row)
        rows.append(full_row)

    record_count, error_count = stream_parser(path, host, collect)
    return rows, record_count, error_count


def parse_qcloud_ydservice_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    return _collect_rows(path, host, stream_qcloud_ydservice_file)


def parse_qcloud_go_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    return _collect_rows(path, host, stream_qcloud_go_file)


def parse_qcloud_scanner_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    return _collect_rows(path, host, stream_qcloud_scanner_file)


def parse_qcloud_ydeyes_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    return _collect_rows(path, host, stream_qcloud_ydeyes_file)
