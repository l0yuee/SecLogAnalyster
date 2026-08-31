from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from seclogx.ingest.logsources.parsers.syslog import extract_auth_events, parse_syslog_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources_linux"


def test_parse_bsd_syslog_file_fields():
    rows, ok, err = parse_syslog_file(FIXTURES / "sample_syslog.log", host="LAB01")
    assert ok == 9
    assert err == 0
    assert len(rows) == 9

    sshd_row = rows[1]
    assert sshd_row["host"] == "LAB01"
    assert sshd_row["hostname"] == "kaligraphite"
    assert sshd_row["app_name"] == "sshd"
    assert sshd_row["proc_id"] == "2345"
    assert sshd_row["message"] == "Accepted password for alice from 10.0.0.5 port 51322 ssh2"
    # no <PRI> in this file's lines -- facility/severity are NULL, not guessed
    assert sshd_row["facility"] is None
    assert sshd_row["severity"] is None
    assert sshd_row["msg_id"] is None
    assert sshd_row["structured_data"] is None


def test_parse_bsd_syslog_infers_year_from_file_mtime(tmp_path: Path):
    p = tmp_path / "syslog"
    p.write_text("Mar  3 04:05:06 host1 sshd[100]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n")
    mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()
    os.utime(p, (mtime, mtime))

    rows, ok, err = parse_syslog_file(p, host="H")
    assert ok == 1
    assert err == 0
    assert rows[0]["time_created"] == "2022-03-03T04:05:06"


def test_parse_bsd_syslog_unparseable_line_counts_as_error(tmp_path: Path):
    p = tmp_path / "syslog"
    p.write_text("this is not a syslog line at all\n")
    rows, ok, err = parse_syslog_file(p, host="H")
    assert ok == 0
    assert err == 1
    assert rows == []


def test_parse_rfc5424_syslog_file_fields_and_structured_data():
    rows, ok, err = parse_syslog_file(FIXTURES / "sample_syslog_rfc5424.log", host="LAB01")
    assert ok == 2
    assert err == 0

    sd_row = rows[0]
    assert sd_row["time_created"] == "2026-08-30T09:30:00.123456+00:00"
    assert sd_row["app_name"] == "sshd"
    assert sd_row["proc_id"] == "2400"
    assert sd_row["msg_id"] == "ID47"
    assert sd_row["facility"] == "auth"
    assert sd_row["severity"] == "crit"
    assert sd_row["structured_data"] == '{"exampleSDID@32473": {"iut": "3", "eventSource": "App"}}'

    no_sd_row = rows[1]
    assert no_sd_row["time_created"] == "2026-08-30T09:31:00+00:00"
    assert no_sd_row["facility"] == "cron"
    assert no_sd_row["severity"] == "info"
    assert no_sd_row["msg_id"] is None
    assert no_sd_row["structured_data"] is None


def test_extract_auth_events_recognizes_each_event_type():
    rows, _, _ = parse_syslog_file(FIXTURES / "sample_syslog.log", host="LAB01")
    df = pd.DataFrame(rows)
    auth = extract_auth_events(df)

    by_type = {row.event_type: row for row in auth.itertuples()}
    assert set(by_type) == {
        "ssh_accepted", "ssh_failed", "ssh_invalid_user", "ssh_disconnected",
        "sudo_command", "session_opened", "account_management",
    }

    accepted = by_type["ssh_accepted"]
    assert accepted.user == "alice"
    assert accepted.source_ip == "10.0.0.5"
    assert accepted.source_port == "51322"
    assert accepted.auth_method == "password"

    failed = by_type["ssh_failed"]
    assert failed.user == "oracle"
    assert failed.source_ip == "203.0.113.7"

    sudo = by_type["sudo_command"]
    assert sudo.user == "alice"
    assert sudo.command == "/usr/bin/apt update"

    session = by_type["session_opened"]
    assert session.user == "root"

    account = by_type["account_management"]
    assert account.user == "bob"

    # CRON and kernel lines don't match any recognized auth shape
    assert "CRON" not in set(auth["app_name"])
    assert "kernel" not in set(auth["app_name"])


def test_extract_auth_events_excludes_unrecognized_lines():
    rows, _, _ = parse_syslog_file(FIXTURES / "sample_syslog.log", host="LAB01")
    df = pd.DataFrame(rows)
    auth = extract_auth_events(df)
    assert len(auth) == 7  # 9 lines total, CRON and kernel excluded


def test_extract_auth_events_on_empty_dataframe_returns_empty_with_columns():
    empty = pd.DataFrame()
    auth = extract_auth_events(empty)
    assert auth.empty
    assert list(auth.columns) == [
        "time_created", "host", "event_type", "user", "source_ip", "source_port",
        "auth_method", "command", "message", "app_name",
    ]
