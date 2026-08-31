from __future__ import annotations

import json
from pathlib import Path

from seclogx.ingest.logsources.parsers.auditd import parse_auditd_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources_linux"


def test_parse_auditd_file_promotes_known_fields():
    rows, ok, err = parse_auditd_file(FIXTURES / "sample_auditd.log", host="LAB01")
    assert ok == 3
    assert err == 0

    syscall_row = next(r for r in rows if r["record_type"] == "SYSCALL")
    assert syscall_row["host"] == "LAB01"
    assert syscall_row["audit_serial"] == 12345
    assert syscall_row["syscall"] == "59"
    assert syscall_row["success"] == "yes"
    assert syscall_row["exe"] == "/bin/bash"
    assert syscall_row["comm"] == "bash"
    assert syscall_row["uid"] == "0"
    assert syscall_row["auid"] == "1000"
    assert syscall_row["pid"] == "1001"
    assert syscall_row["ppid"] == "1000"
    assert syscall_row["key"] == "privilege_escalation"
    assert syscall_row["time_created"] == "2023-07-22T04:26:40.123000+00:00"


def test_parse_auditd_file_remainder_goes_to_fields_not_promoted_columns():
    rows, _, _ = parse_auditd_file(FIXTURES / "sample_auditd.log", host="LAB01")
    syscall_row = next(r for r in rows if r["record_type"] == "SYSCALL")
    fields = json.loads(syscall_row["fields"])
    # promoted keys are not duplicated into the remainder
    for promoted in ("syscall", "success", "exe", "comm", "uid", "auid", "pid", "ppid", "key"):
        assert promoted not in fields
    assert fields["arch"] == "c000003e"
    assert fields["items"] == "2"
    assert fields["subj"] == "unconfined"


def test_parse_auditd_file_related_lines_share_audit_serial():
    rows, _, _ = parse_auditd_file(FIXTURES / "sample_auditd.log", host="LAB01")
    syscall_row = next(r for r in rows if r["record_type"] == "SYSCALL")
    execve_row = next(r for r in rows if r["record_type"] == "EXECVE")
    user_auth_row = next(r for r in rows if r["record_type"] == "USER_AUTH")
    assert syscall_row["audit_serial"] == execve_row["audit_serial"] == 12345
    assert user_auth_row["audit_serial"] == 12346

    execve_fields = json.loads(execve_row["fields"])
    assert execve_fields["a0"] == "sudo"
    assert execve_fields["a1"] == "su"

    assert user_auth_row["exe"] == "/usr/bin/sudo"
    user_auth_fields = json.loads(user_auth_row["fields"])
    assert user_auth_fields["acct"] == "root"
    assert user_auth_fields["res"] == "success"


def test_parse_auditd_file_malformed_line_counts_as_error(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text("this line has no audit header at all\n")
    rows, ok, err = parse_auditd_file(p, host="H")
    assert ok == 0
    assert err == 1
    assert rows == []
