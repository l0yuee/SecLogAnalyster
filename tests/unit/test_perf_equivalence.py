"""Equivalence guards for optimizations that replaced a slow-but-obvious
implementation with a faster one. Each test pins the new behavior to the
old one rather than to hand-written expectations, so a future change that
speeds something up further can't quietly change what it produces.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

from seclogx.case import Case
from seclogx.ingest.logsources.parsers.syslog import extract_auth_events
from seclogx.ingest.logsources.parsers.webaccess import _parse_time


def _strptime_reference(raw: str) -> str | None:
    """The implementation `_parse_time` replaced."""
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None


@pytest.mark.parametrize(
    "raw",
    [
        "10/Oct/2023:13:55:36 +0000",       # the canonical fixed-width shape
        "01/Jan/2026:00:00:00 +0000",
        "31/Dec/1999:23:59:59 -0500",       # negative offset
        "15/Jun/2024:12:30:45 +0530",       # offset with minutes
        "1/Oct/2023:1:5:6 -0530",           # unpadded -> strptime fallback
        "10/Oct/2023:13:55:36",             # no offset -> fallback (rejected)
        "32/Oct/2023:13:55:36 +0000",       # impossible day
        "10/Xxx/2023:13:55:36 +0000",       # bad month name
        "10-Oct-2023:13:55:36 +0000",       # wrong separators
        "not a timestamp",
        "",
        "10/Feb/2024:00:00:00 +0000",       # leap year
        "29/Feb/2023:00:00:00 +0000",       # not a leap year -> invalid
    ],
)
def test_clf_time_parsing_matches_strptime_exactly(raw: str):
    assert _parse_time(raw) == _strptime_reference(raw)


def _ingest_syslog(tmp_path: Path, lines: list[str]) -> Case:
    src = tmp_path / "evidence"
    src.mkdir(parents=True)
    (src / "auth.log").write_text("".join(line if line.endswith("\n") else line + "\n" for line in lines))
    case = Case.create("authcase", case_root=tmp_path / "cases")
    case.ingest([str(src)], workers=1)
    return case


def test_auth_events_sql_prefilter_matches_full_table_extraction(tmp_path: Path):
    """`Case.auth_events()` now narrows candidates in SQL instead of
    pulling all of `syslog` into memory. The filter is meant to be a
    strict superset of what the heuristic accepts, so the result must be
    identical to running the heuristic over the whole table."""
    lines = [
        # recognized shapes
        "<34>1 2026-01-01T00:00:00Z h1 sshd 1 - - Accepted password for alice from 10.0.0.5 port 2222 ssh2",
        "<34>1 2026-01-01T00:01:00Z h1 sshd 2 - - Failed password for invalid user bob from 10.0.0.6 port 2223 ssh2",
        "<34>1 2026-01-01T00:02:00Z h1 sshd 3 - - Invalid user carol from 10.0.0.7",
        "<34>1 2026-01-01T00:03:00Z h1 sudo 4 - - dave : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "<34>1 2026-01-01T00:04:00Z h1 su 5 - - pam_unix(su:session): session opened for user root",
        "<34>1 2026-01-01T00:05:00Z h1 useradd 6 - - new user: name=eve, UID=1001",
        "<34>1 2026-01-01T00:06:00Z h1 sshd 7 - - Connection closed by 10.0.0.8",
        # noise the filter must exclude without changing the outcome
        "<34>1 2026-01-01T00:07:00Z h1 kernel 8 - - eth0: link up",
        "<34>1 2026-01-01T00:08:00Z h1 cron 9 - - (root) CMD (/usr/bin/backup)",
        "<34>1 2026-01-01T00:09:00Z h1 sshd 10 - - Server listening on 0.0.0.0 port 22",
        "<34>1 2026-01-01T00:10:00Z h1 systemd 11 - - Started Daily apt upgrade",
    ]
    case = _ingest_syslog(tmp_path, lines)

    optimized = case.auth_events()
    reference = extract_auth_events(case.db.sql("SELECT * FROM syslog ORDER BY time_created"))

    pd.testing.assert_frame_equal(
        optimized.reset_index(drop=True), reference.reset_index(drop=True)
    )
    assert set(optimized["event_type"]) == {
        "ssh_accepted", "ssh_failed", "ssh_invalid_user", "ssh_disconnected",
        "sudo_command", "session_opened", "account_management",
    }


def test_auth_events_on_a_case_without_syslog_is_empty_not_an_error(tmp_path: Path):
    case = Case.create("nosyslog", case_root=tmp_path / "cases")
    auth = case.auth_events()
    assert auth.empty
    assert "event_type" in auth.columns
