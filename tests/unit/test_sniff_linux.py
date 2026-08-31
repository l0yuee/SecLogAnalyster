from __future__ import annotations

from pathlib import Path

from seclogx.ingest.logsources.sniff import KIND_AUDITD, KIND_JOURNAL_EXPORT, KIND_SYSLOG, classify_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources_linux"


def test_classify_bsd_syslog():
    assert classify_file(FIXTURES / "sample_syslog.log") == KIND_SYSLOG


def test_classify_rfc5424_syslog():
    assert classify_file(FIXTURES / "sample_syslog_rfc5424.log") == KIND_SYSLOG


def test_classify_auditd():
    assert classify_file(FIXTURES / "sample_auditd.log") == KIND_AUDITD


def test_classify_journal_export():
    assert classify_file(FIXTURES / "sample_journal.json") == KIND_JOURNAL_EXPORT


def test_classify_unrecognized_content_returns_none(tmp_path: Path):
    p = tmp_path / "notes.txt"
    p.write_text("just some plain notes, not a log of any kind\nsecond line\n")
    assert classify_file(p) is None


def test_classify_plain_json_without_journal_markers_is_not_journal_export(tmp_path: Path):
    p = tmp_path / "data.json"
    p.write_text('{"foo": "bar", "baz": 1}\n')
    assert classify_file(p) is None
