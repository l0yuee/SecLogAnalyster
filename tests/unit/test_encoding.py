"""Coverage for the encoding-robustness fixes: GBK/GB2312 (via stdlib
gb18030) decode support for the aux-log parsers, and the Scheduled Tasks
XML parser no longer crashing on a wrong-encoding guess or malformed XML.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seclogx.ingest.common import StageStatus
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.parsers.scheduled_tasks import RejectedTaskXmlError, parse_task_xml
from seclogx.ingest.logsources.sniff import KIND_SCHEDULED_TASK, _decode_lines, _decode_text
from seclogx.ingest.logsources.stage import stage_aux_file


def test_decode_text_round_trips_gb18030():
    text = "系统日志: 用户登录失败"
    raw = text.encode("gb18030")
    assert _decode_text(raw) == text


def test_decode_text_round_trips_utf8():
    text = "hello world"
    assert _decode_text(text.encode("utf-8-sig")) == text


def test_decode_lines_splits_gb18030_content():
    lines = ["用户: root 登录成功", "用户: admin 登录失败"]
    raw = "\n".join(lines).encode("gb18030")
    assert _decode_lines(raw) == lines


def test_decode_text_never_raises_on_arbitrary_binary():
    # A byte sequence unlikely to be valid UTF-8/UTF-16/GB18030 -- must
    # still come back as *some* string, never raise.
    raw = bytes(range(256)) * 4
    result = _decode_text(raw)
    assert isinstance(result, str)


def test_parse_task_xml_handles_utf16_encoding(tmp_path: Path):
    xml = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Author>NT AUTHORITY\\SYSTEM</Author>\n"
        "    <Description>Windows Defender scheduled scan</Description>\n"
        "  </RegistrationInfo>\n"
        "  <Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>\n"
        '  <Actions Context="Author">\n'
        "    <Exec>\n"
        "      <Command>C:\\Program Files\\Windows Defender\\MpCmdRun.exe</Command>\n"
        "      <Arguments>-Scan -ScheduleJob</Arguments>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )
    p = tmp_path / "task_utf16"
    p.write_bytes(xml.encode("utf-16"))

    row = parse_task_xml(p, host="WKS01")
    assert row["author"] == r"NT AUTHORITY\SYSTEM"
    assert row["action_command"] == r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    assert row["action_arguments"] == "-Scan -ScheduleJob"
    assert row["action_types"] == "Exec"


def test_parse_task_xml_malformed_xml_raises_rejected_not_parse_error(tmp_path: Path):
    p = tmp_path / "truncated.xml"
    p.write_text(
        '<?xml version="1.0"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo><Author>test</Author>"  # deliberately truncated / unclosed
    )
    with pytest.raises(RejectedTaskXmlError):
        parse_task_xml(p, host="WKS01")


def test_stage_aux_file_reports_malformed_task_xml_as_failed_not_a_crash(tmp_path: Path):
    p = tmp_path / "truncated.xml"
    p.write_text(
        '<?xml version="1.0"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo><Author>test</Author>"
    )
    cf = ClassifiedFile(path=p, host="WKS01", size_bytes=p.stat().st_size, kind=KIND_SCHEDULED_TASK)
    result = stage_aux_file(cf, tmp_path / "staging")
    assert result.status == StageStatus.FAILED
    assert result.ndjson_path is None
    assert "malformed" in (result.error_message or "").lower()
