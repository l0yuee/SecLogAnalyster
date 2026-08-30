from __future__ import annotations

import json
from pathlib import Path

import pytest

from seclogx.ingest.common import SourceSpec
from seclogx.ingest.logsources.discovery import discover_and_classify
from seclogx.ingest.logsources.orchestrator import run_aux_ingest
from seclogx.ingest.logsources.parsers.exchange import parse_exchange_csv
from seclogx.ingest.logsources.parsers.iis import parse_iis_file
from seclogx.ingest.logsources.parsers.scheduled_tasks import parse_task_xml
from seclogx.ingest.logsources.parsers.webaccess import parse_web_access_file
from seclogx.ingest.logsources.parsers.weberror import (
    parse_apache_error_file,
    parse_iis_httperr_file,
    parse_nginx_error_file,
    parse_tomcat_error_file,
)
from seclogx.ingest.logsources.sniff import (
    KIND_EXCHANGE_MESSAGE_TRACKING,
    KIND_IIS,
    KIND_IIS_HTTPERR,
    KIND_SCHEDULED_TASK,
    KIND_WEB_ACCESS,
    KIND_WEB_ERROR_APACHE,
    KIND_WEB_ERROR_NGINX,
    KIND_WEB_ERROR_TOMCAT,
    classify_file,
    guess_web_log_type,
)

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
    from seclogx.ingest.logsources.sniff import KIND_EXCHANGE_GENERIC

    assert classify_file(FIXTURES / "sample_httpproxy.csv") == KIND_EXCHANGE_GENERIC


def test_classify_web_error_logs():
    assert classify_file(FIXTURES / "sample_nginx_error.log") == KIND_WEB_ERROR_NGINX
    assert classify_file(FIXTURES / "sample_apache_error.log") == KIND_WEB_ERROR_APACHE
    assert classify_file(FIXTURES / "sample_tomcat_error.log") == KIND_WEB_ERROR_TOMCAT
    assert classify_file(FIXTURES / "sample_iis_httperr.log") == KIND_IIS_HTTPERR


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
    from seclogx.ingest.logsources.sniff import KIND_EXCHANGE_GENERIC

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


def test_parse_nginx_error_file():
    rows, ok, err = parse_nginx_error_file(FIXTURES / "sample_nginx_error.log", host="WEB01")
    assert ok == 2
    assert err == 0
    assert rows[0]["log_type"] == "nginx"
    assert rows[0]["severity"] == "error"
    assert rows[0]["pid_or_thread"] == "12345#0"
    assert rows[0]["client_ip"] == "203.0.113.9"
    assert "shell.php" in rows[0]["message"]
    assert rows[1]["severity"] == "warn"


def test_parse_apache_error_file():
    rows, ok, err = parse_apache_error_file(FIXTURES / "sample_apache_error.log", host="WEB01")
    assert ok == 2
    assert err == 0
    assert rows[0]["log_type"] == "apache"
    assert rows[0]["severity"] == "error"
    assert rows[0]["pid_or_thread"] == "12345"
    assert rows[0]["client_ip"] == "203.0.113.9"
    assert rows[0]["client_port"] == "5678"
    assert "Invalid URI" in rows[0]["message"]


def test_parse_tomcat_error_file():
    rows, ok, err = parse_tomcat_error_file(FIXTURES / "sample_tomcat_error.log", host="WEB01")
    assert ok == 2
    assert err == 0
    assert rows[0]["log_type"] == "tomcat"
    assert rows[0]["severity"] == "SEVERE"
    assert rows[0]["logger"] == "org.apache.catalina.core.StandardWrapperValve.invoke"
    assert "NullPointerException" in rows[0]["message"]
    assert "com.evil.Shell" in rows[0]["message"]
    assert rows[1]["severity"] == "INFO"


def test_parse_iis_httperr_file():
    rows, ok, err = parse_iis_httperr_file(FIXTURES / "sample_iis_httperr.log", host="EXCH01")
    assert ok == 1
    assert err == 0
    row = rows[0]
    assert row["log_type"] == "iis_httperr"
    assert row["client_ip"] == "203.0.113.9"
    assert row["client_port"] == "5678"
    assert row["method"] == "GET"
    assert row["uri"] == "/shell.aspx"
    assert row["status"] == 400
    assert row["message"] == "BadRequest"


# -- end-to-end aux ingest --------------------------------------------------------


def test_run_aux_ingest_writes_all_tables(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    report = run_aux_ingest(case_dir, [SourceSpec(path=FIXTURES, host="LAB01")], workers=1)

    assert report.files_discovered == 10
    assert report.files_ok == 10
    assert report.files_failed == 0
    assert report.rows_written.get("scheduled_tasks") == 2  # sample_task.xml + benign_task.xml
    assert report.rows_written.get("web_logs") == 4  # 2 IIS + 2 nginx rows
    assert report.rows_written.get("web_error_logs") == 7  # 2 nginx + 2 apache + 2 tomcat + 1 IIS HTTPERR
    assert report.rows_written.get("exchange_message_tracking") == 1
    assert report.rows_written.get("exchange_logs") == 1

    df = report.to_dataframe()
    assert len(df) == 10
    assert set(df["status"]) == {"ok"}
    assert "rows" not in df.columns

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


def test_case_table_accessors_return_dataframes(tmp_path: Path):
    """Every log family should be reachable as a plain DataFrame, the same
    way `events` is via summary()/hosts()/etc."""
    import pandas as pd

    from seclogx.case import Case

    case = Case.create("dfparity", case_root=tmp_path / "cases")
    case.ingest([f"{FIXTURES}:LAB01"])

    for df in (
        case.scheduled_tasks(),
        case.web_logs(),
        case.web_error_logs(),
        case.exchange_message_tracking(),
        case.exchange_logs(),
        case.db.table("web_logs"),
    ):
        assert isinstance(df, pd.DataFrame)
        assert not df.empty

    assert set(case.web_logs(log_type="nginx")["log_type"]) == {"nginx"}
    assert set(case.web_error_logs(log_type="apache")["log_type"]) == {"apache"}
    assert set(case.exchange_logs(log_type="HttpProxy")["log_type"]) == {"HttpProxy"}

    # a table the case genuinely has no data for returns an empty DataFrame, not an error
    empty_case = Case.create("emptydf", case_root=tmp_path / "cases")
    assert case.db.table("nonexistent_table").empty
    assert isinstance(empty_case.web_logs(), pd.DataFrame)


def test_case_chunked_accessors_match_eager(tmp_path: Path):
    """Every log family's *_chunks() accessor should reconstruct exactly
    what the eager accessor returns -- the whole point is bounded memory,
    not different data."""
    import pandas as pd

    from seclogx.case import Case

    case = Case.create("chunkparity", case_root=tmp_path / "cases")
    case.ingest([f"{FIXTURES}:LAB01"])

    pairs = [
        (case.web_logs(), case.web_logs_chunks()),
        (case.web_error_logs(), case.web_error_logs_chunks()),
        (case.scheduled_tasks(), case.scheduled_tasks_chunks()),
        (case.exchange_message_tracking(), case.exchange_message_tracking_chunks()),
        (case.exchange_logs(), case.exchange_logs_chunks()),
    ]
    for eager, chunked in pairs:
        combined = pd.concat(list(chunked), ignore_index=True) if not eager.empty else pd.DataFrame()
        assert len(combined) == len(eager)

    # log_type-filtered chunked variants behave the same as their eager counterparts
    assert set(pd.concat(list(case.web_logs_chunks(log_type="nginx")))["log_type"]) == {"nginx"}
    assert set(pd.concat(list(case.web_error_logs_chunks(log_type="apache")))["log_type"]) == {"apache"}
    assert set(pd.concat(list(case.exchange_logs_chunks(log_type="HttpProxy")))["log_type"]) == {"HttpProxy"}

    # a table the case has no data for yields an empty iterator, not an error
    empty_case = Case.create("chunkempty", case_root=tmp_path / "cases")
    assert list(empty_case.web_logs_chunks()) == []
    assert list(empty_case.scheduled_tasks_chunks()) == []
