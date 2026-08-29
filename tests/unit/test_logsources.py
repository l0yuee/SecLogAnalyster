from __future__ import annotations

import json
from pathlib import Path

import pytest

from seclogx.logsources.discovery import discover_and_classify
from seclogx.logsources.exchange import parse_exchange_csv
from seclogx.logsources.iis import parse_iis_file
from seclogx.logsources.ingest import run_aux_ingest
from seclogx.logsources.scheduled_tasks import parse_task_xml
from seclogx.logsources.sniff import (
    KIND_EXCHANGE_MESSAGE_TRACKING,
    KIND_IIS,
    KIND_SCHEDULED_TASK,
    KIND_WEB_ACCESS,
    classify_file,
    guess_web_log_type,
)
from seclogx.logsources.webaccess import parse_web_access_file
from seclogx.discovery import SourceSpec

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources"


# -- classification -----------------------------------------------------------


def test_classify_scheduled_task():
    assert classify_file(FIXTURES / "sample_task.xml") == KIND_SCHEDULED_TASK


def test_classify_iis():
    assert classify_file(FIXTURES / "sample_iis.log") == KIND_IIS


def test_classify_web_access():
    assert classify_file(FIXTURES / "sample_nginx_access.log") == KIND_WEB_ACCESS


def test_classify_exchange_message_tracking():
    assert classify_file(FIXTURES / "sample_message_tracking.csv") == KIND_EXCHANGE_MESSAGE_TRACKING


def test_classify_exchange_generic():
    from seclogx.logsources.sniff import KIND_EXCHANGE_GENERIC

    assert classify_file(FIXTURES / "sample_httpproxy.csv") == KIND_EXCHANGE_GENERIC


def test_classify_unknown_returns_none(tmp_path: Path):
    p = tmp_path / "notes.txt"
    p.write_text("just some random forensic notes, nothing structured here\nline two\n")
    assert classify_file(p) is None


def test_guess_web_log_type_from_path(tmp_path: Path):
    assert guess_web_log_type(Path("/evidence/var/log/nginx/access.log")) == "nginx"
    assert guess_web_log_type(Path("/evidence/tomcat/logs/localhost_access_log.2026-01-02.txt")) == "tomcat"
    assert guess_web_log_type(Path("/evidence/var/log/apache2/access.log")) == "apache"
    assert guess_web_log_type(Path("/evidence/somewhere/access.log")) == "web_access"


# -- parsers --------------------------------------------------------------------


def test_parse_task_xml():
    row = parse_task_xml(FIXTURES / "sample_task.xml", host="WKS01")
    assert row["host"] == "WKS01"
    assert row["author"] == r"EVILCORP\attacker"
    assert row["hidden"] is True
    assert row["enabled"] is True
    assert row["principal_user_id"] == "S-1-5-18"
    assert row["principal_run_level"] == "HighestAvailable"
    assert "powershell.exe" in row["actions"]
    assert "TimeTrigger" in row["triggers"]


def test_parse_task_xml_rejects_doctype(tmp_path: Path):
    p = tmp_path / "evil.xml"
    p.write_text(
        '<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"></Task>'
    )
    with pytest.raises(ValueError):
        parse_task_xml(p, host="WKS01")


def test_parse_iis_file():
    rows, ok, err = parse_iis_file(FIXTURES / "sample_iis.log", host="EXCH01")
    assert ok == 2
    assert err == 0
    assert rows[0]["log_type"] == "iis"
    assert rows[0]["client_ip"] == "203.0.113.7"
    assert rows[0]["uri_stem"] == "/owa/auth/logon.aspx"
    assert rows[0]["uri_query"] is None
    assert rows[0]["status"] == 200
    assert rows[1]["uri_query"] == "cmd=whoami"


def test_parse_web_access_file():
    rows, ok, err = parse_web_access_file(FIXTURES / "sample_nginx_access.log", host="WEB01", log_type="nginx")
    assert ok == 2
    assert err == 0
    assert rows[0]["client_ip"] == "203.0.113.9"
    assert rows[0]["method"] == "GET"
    assert rows[0]["uri_stem"] == "/index.html"
    assert rows[0]["status"] == 200
    assert rows[1]["status"] == 403
    assert rows[1]["user_agent"] == "python-requests/2.31"


def test_parse_exchange_message_tracking():
    table, rows, ok, err = parse_exchange_csv(
        FIXTURES / "sample_message_tracking.csv", host="MBX01", subkind=KIND_EXCHANGE_MESSAGE_TRACKING
    )
    assert table == "exchange_message_tracking"
    assert ok == 1
    assert err == 0
    row = rows[0]
    assert row["sender_address"] == "attacker@evil.example"
    assert row["recipient_address"] == "victim@corp.example"
    assert row["message_subject"] == "Invoice overdue"
    assert row["total_bytes"] == 4096


def test_parse_exchange_generic_catchall():
    from seclogx.logsources.sniff import KIND_EXCHANGE_GENERIC

    table, rows, ok, err = parse_exchange_csv(
        FIXTURES / "sample_httpproxy.csv", host="MBX01", subkind=KIND_EXCHANGE_GENERIC
    )
    assert table == "exchange_logs"
    assert ok == 1
    assert err == 0
    row = rows[0]
    assert row["log_type"] == "HttpProxy"
    assert row["time_created"] is not None
    fields = json.loads(row["fields"])
    assert fields["AuthenticatedUser"] == "attacker@evil.example"
    assert fields["UrlStem"] == "/owa/"


# -- end-to-end aux ingest --------------------------------------------------------


def test_run_aux_ingest_writes_all_tables(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    report = run_aux_ingest(case_dir, [SourceSpec(path=FIXTURES, host="LAB01")], workers=1)

    assert report.files_discovered == 6
    assert report.files_ok == 6
    assert report.files_failed == 0
    assert report.rows_written.get("scheduled_tasks") == 2  # sample_task.xml + benign_task.xml
    assert report.rows_written.get("web_logs") == 4  # 2 IIS + 2 nginx rows
    assert report.rows_written.get("exchange_message_tracking") == 1
    assert report.rows_written.get("exchange_logs") == 1

    import duckdb

    con = duckdb.connect()
    tasks = con.execute(
        f"SELECT * FROM read_parquet('{case_dir / 'lake' / 'scheduled_tasks' / '**' / '*.parquet'}', hive_partitioning=true)"
    ).fetchdf()
    assert len(tasks) == 2
    assert set(tasks["host"]) == {"LAB01"}

    web = con.execute(
        f"SELECT * FROM read_parquet('{case_dir / 'lake' / 'web_logs' / '**' / '*.parquet'}', "
        "hive_partitioning=true, union_by_name=true)"
    ).fetchdf()
    assert len(web) == 4
    assert set(web["log_type"]) == {"iis", "nginx"}


def test_case_suspicious_tasks_filters_benign(tmp_path: Path):
    from seclogx.case import Case

    case = Case.create("tasktest", case_root=tmp_path / "cases")
    case.ingest([f"{FIXTURES}:LAB01"])

    all_tasks = case.query("SELECT task_name FROM scheduled_tasks")
    assert set(all_tasks["task_name"]) == {"sample_task.xml", "benign_task.xml"}

    suspicious = case.suspicious_tasks()
    assert set(suspicious["task_name"]) == {"sample_task.xml"}
