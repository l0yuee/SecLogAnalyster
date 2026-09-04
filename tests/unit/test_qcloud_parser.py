from __future__ import annotations

import json
from pathlib import Path

from seclogx.case import Case
from seclogx.ingest.common import SourceSpec
from seclogx.ingest.logsources.orchestrator import run_aux_ingest
from seclogx.ingest.logsources.parsers.qcloud import (
    guess_qcloud_log_type,
    parse_qcloud_go_file,
    parse_qcloud_scanner_file,
    parse_qcloud_ydeyes_file,
    parse_qcloud_ydservice_file,
)
from seclogx.ingest.logsources.sniff import (
    KIND_QCLOUD_GO,
    KIND_QCLOUD_SCANNER,
    KIND_QCLOUD_YDEYES,
    KIND_QCLOUD_YDSERVICE,
    classify_file,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "qcloud_logs"


def test_classifies_all_qcloud_text_log_formats():
    assert classify_file(FIXTURES / "ydservice.20260904.log") == KIND_QCLOUD_YDSERVICE
    assert classify_file(FIXTURES / "hids.log") == KIND_QCLOUD_GO
    assert classify_file(FIXTURES / "ydlive.log") == KIND_QCLOUD_GO
    assert classify_file(FIXTURES / "vul_scan.log") == KIND_QCLOUD_SCANNER
    assert classify_file(FIXTURES / "YDEyes" / "log.txt") == KIND_QCLOUD_YDEYES


def test_labels_all_known_qcloud_components():
    expected = {
        "ydservice.20260904.log": "ydservice",
        "hids.log.bak": "hids",
        "ydlive.log": "ydlive",
        "vul_scan.log.2026-07-31": "vul_scan",
        "baseline_scan.log": "baseline_scan",
        "YDFlame.log": "ydflame",
        "YDFlame.err": "ydflame",
        "YDUtils.log": "ydutils",
        "YDQuaraV2.log": "ydquarav2",
    }
    for name, log_type in expected.items():
        assert guess_qcloud_log_type(Path(name), "fallback") == log_type
    assert guess_qcloud_log_type(Path("YDEyes") / "log.txt", "fallback") == "ydeyes"


def test_generic_go_and_bracket_logs_are_not_misclassified(tmp_path: Path):
    go_log = tmp_path / "application.log"
    go_log.write_text("2026-01-01 00:00:00[INFO][main.go:10]ordinary application start\n")
    scanner_log = tmp_path / "scanner.log"
    scanner_log.write_text("[2026-01-01 00:00:00] [INFO] ordinary scanner start\n")

    assert classify_file(go_log) is None
    assert classify_file(scanner_log) is None


def test_parse_ydservice_security_fields():
    rows, ok, err = parse_qcloud_ydservice_file(FIXTURES / "ydservice.20260904.log", "CVM01")
    assert (ok, err) == (4, 0)

    login = rows[1]
    assert login["log_type"] == "ydservice"
    assert login["severity"] == "WRN"
    assert login["module"] == "Detection"
    assert login["source_line"] == 206
    assert login["process_id"] == 753513
    assert login["thread_id"] == 753665
    assert login["event_type"] == "login_failure"
    assert login["user_name"] == "root"
    assert login["source_ip"] == "203.0.113.10"
    assert login["destination_port"] == 22
    assert login["blocked"] is True
    assert login["raw_line"].startswith("2026-09-04 00:02:41.183")

    malware = rows[2]
    assert malware["event_type"] == "malware_detection"
    assert malware["subject_process_id"] == 4242
    assert malware["file_md5"] == "45cb795ea7f4d89c422f6e16ac777a89"
    assert malware["file_path"] == "/tmp/suspicious.bin"
    assert malware["trace_id"] == "c5f85795e2c845db9639330f0a36798e"
    assert json.loads(malware["extra"])["report_mod"] == 7

    accepted = rows[3]
    assert accepted["event_type"] == "login_success"
    assert accepted["user_name"] == "analyst"
    assert accepted["source_ip"] == "198.51.100.8"
    assert accepted["destination_port"] == 45678


def test_parse_go_scanner_quara_and_ydeyes_formats():
    hids, ok, err = parse_qcloud_go_file(FIXTURES / "hids.log", "CVM01")
    assert (ok, err) == (2, 0)
    assert hids[0]["log_type"] == "hids"
    assert hids[0]["code_file"] == "block.go"
    assert hids[0]["module"] == "block"
    assert hids[0]["event_type"] == "ip_blocklist"
    assert hids[0]["source_ip"] == "192.0.2.44"

    scanner, ok, err = parse_qcloud_scanner_file(FIXTURES / "vul_scan.log", "CVM01")
    assert (ok, err) == (2, 0)
    assert scanner[0]["log_type"] == "vul_scan"
    assert scanner[0]["event_type"] == "command_execution"
    assert json.loads(scanner[0]["extra"]) == {
        "uid": 65534,
        "gid": 65534,
        "command": "/bin/bash -c 'uname -r'",
    }

    quara, ok, err = parse_qcloud_go_file(FIXTURES / "YDQuaraV2.log", "CVM01")
    assert (ok, err) == (1, 0)
    assert quara[0]["log_type"] == "ydquarav2"
    assert quara[0]["event_type"] == "malware_scan"
    assert quara[0]["file_path"] == "/tmp/sample.bin"
    assert json.loads(quara[0]["extra"]) == {"file_exists": True, "process_exists": False}

    ydeyes, ok, err = parse_qcloud_ydeyes_file(FIXTURES / "YDEyes" / "log.txt", "CVM01")
    assert (ok, err) == (2, 0)
    assert ydeyes[0]["log_type"] == "ydeyes"
    assert ydeyes[0]["module"] == "YDEyes"
    assert ydeyes[0]["severity"] is None


def test_qcloud_parser_reports_unmatched_nonblank_lines(tmp_path: Path):
    path = tmp_path / "ydservice.bad.log"
    path.write_text(
        "not a valid YDService line\n"
        "2026-09-04 00:00:00.001 1 2 INF YDHealth:3 valid\n"
    )
    rows, ok, err = parse_qcloud_ydservice_file(path, "CVM01")
    assert len(rows) == 1
    assert (ok, err) == (1, 1)


def test_qcloud_streaming_parser_handles_supported_text_encodings(tmp_path: Path):
    line = "[2026-09-04 00:00:00] [INFO] 扫描完成\n"
    for encoding in ("utf-8-sig", "utf-16", "gb18030"):
        path = tmp_path / f"vul_scan.{encoding}.log"
        path.write_bytes(line.encode(encoding))
        rows, ok, err = parse_qcloud_scanner_file(path, "CVM01")
        assert (ok, err) == (1, 0)
        assert rows[0]["message"] == "扫描完成"


def test_qcloud_multiline_records_are_preserved_and_enriched(tmp_path: Path):
    ydservice = tmp_path / "ydservice.20260904.log"
    ydservice.write_text(
        "2026-09-04 01:06:15.535 1 2 INF AccountInfo:423 "
        "user_name is root, group_name is root, shell_path is /bin/bash\n"
        ", canlogin is 1, privilege is 0,  modify_type is 1\n"
    )
    rows, ok, err = parse_qcloud_ydservice_file(ydservice, "CVM01")
    assert (ok, err) == (1, 0)
    assert rows[0]["event_type"] == "account_inventory"
    assert rows[0]["user_name"] == "root"
    assert json.loads(rows[0]["extra"]) == {
        "group_name": "root",
        "shell_path": "/bin/bash",
        "can_login": True,
        "privilege": 0,
        "modify_type": 1,
    }
    assert "\n, canlogin is 1" in rows[0]["raw_line"]

    scanner = tmp_path / "vul_scan.log"
    scanner.write_text(
        "[2026-08-14 05:09:00] [INFO] ps info ==> [root 1 command\n"
        "root 2 grep command]\n"
    )
    rows, ok, err = parse_qcloud_scanner_file(scanner, "CVM01")
    assert (ok, err) == (1, 0)
    assert rows[0]["message"].endswith("root 2 grep command]")


def test_qcloud_logs_ingest_and_case_accessors(tmp_path: Path):
    case = Case.create("qcloud", case_root=tmp_path / "cases")
    report = run_aux_ingest(case.case_dir, [SourceSpec(path=FIXTURES, host="CVM01")], workers=1)

    assert report.files_discovered == 6
    assert report.files_ok == 6
    assert report.files_partial == 0
    assert report.files_failed == 0
    assert report.files_unknown == 0
    assert report.rows_written == {"qcloud_logs": 12}

    rows = case.qcloud_logs()
    assert len(rows) == 12
    assert set(rows["log_type"]) == {"ydservice", "hids", "ydlive", "vul_scan", "ydquarav2", "ydeyes"}
    assert len(case.qcloud_logs(log_type="ydservice")) == 4
    assert sum(len(chunk) for chunk in case.qcloud_logs_chunks(chunksize=2)) == 12
    assert case.search("qcloud_logs", eq={"event_type": "malware_detection"}).shape[0] == 1
