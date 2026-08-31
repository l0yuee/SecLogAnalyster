from __future__ import annotations

import json
from pathlib import Path

from seclogx.ingest.logsources.parsers.journal import parse_journal_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources_linux"


def test_parse_journal_file_promotes_known_fields():
    rows, ok, err = parse_journal_file(FIXTURES / "sample_journal.json", host="LAB01")
    assert ok == 2
    assert err == 0

    ssh_row = rows[0]
    assert ssh_row["host"] == "LAB01"
    assert ssh_row["hostname"] == "kalibox"
    assert ssh_row["unit"] == "ssh.service"
    assert ssh_row["syslog_identifier"] == "sshd"
    assert ssh_row["priority"] == "6"
    assert ssh_row["pid"] == "3000"
    assert ssh_row["uid"] == "0"
    assert ssh_row["comm"] == "sshd"
    assert ssh_row["exe"] == "/usr/sbin/sshd"
    assert ssh_row["message"] == "Accepted publickey for dave from 192.0.2.5 port 22 ssh2"
    assert ssh_row["time_created"] == "2023-07-22T04:26:40+00:00"


def test_parse_journal_file_remainder_excludes_dropped_and_promoted_fields():
    rows, _, _ = parse_journal_file(FIXTURES / "sample_journal.json", host="LAB01")
    ssh_fields = json.loads(rows[0]["fields"])
    assert "__CURSOR" not in ssh_fields
    assert "__REALTIME_TIMESTAMP" not in ssh_fields
    assert "__MONOTONIC_TIMESTAMP" not in ssh_fields
    assert "MESSAGE" not in ssh_fields
    assert ssh_fields == {"_BOOT_ID": "deadbeef"}

    app_fields = json.loads(rows[1]["fields"])
    assert app_fields == {"_BOOT_ID": "deadbeef", "CODE_FILE": "main.c", "CODE_LINE": "42"}


def test_parse_journal_file_malformed_json_line_counts_as_error(tmp_path: Path):
    p = tmp_path / "journal.json"
    p.write_text('{"not": "closed"\n')
    rows, ok, err = parse_journal_file(p, host="H")
    assert ok == 0
    assert err == 1
    assert rows == []


def test_parse_journal_file_non_object_line_counts_as_error(tmp_path: Path):
    p = tmp_path / "journal.json"
    p.write_text("[1, 2, 3]\n")
    rows, ok, err = parse_journal_file(p, host="H")
    assert ok == 0
    assert err == 1
    assert rows == []
