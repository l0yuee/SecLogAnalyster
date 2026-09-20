from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pytest
from regipy.exceptions import RegipyException
from regipy.structs import REGF_HEADER_SIZE

from registry_hive_builder import build_hive
from seclogx.ingest.logsources.parsers import auditd, dblogs, journal, qcloud, registry, syslog


FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.parametrize(
    "parser, fixture",
    [
        (syslog.parse_syslog_file, "logsources_linux/sample_syslog.log"),
        (syslog.parse_syslog_file, "logsources_linux/sample_syslog_rfc5424.log"),
        (auditd.parse_auditd_file, "logsources_linux/sample_auditd.log"),
        (journal.parse_journal_file, "logsources_linux/sample_journal.json"),
        (dblogs.parse_mysql_error_file, "db_logs/mysql_error.log"),
        (dblogs.parse_mysql_general_file, "db_logs/mysql_general.log"),
        (dblogs.parse_mysql_slow_file, "db_logs/mysql_slow.log"),
        (dblogs.parse_postgresql_file, "db_logs/postgresql.log"),
        (dblogs.parse_mssql_file, "db_logs/mssql_errorlog"),
        (dblogs.parse_oracle_alert_file, "db_logs/oracle_alert.log"),
        (registry.parse_registry_hive_file, "registry/SOFTWARE"),
    ],
)
def test_emit_preserves_rows_counts_and_avoids_whole_file_read(parser, fixture, monkeypatch):
    path = FIXTURES / fixture
    expected, expected_ok, expected_errors = parser(path, "HOST")

    def forbid_whole_read(self):
        pytest.fail("streaming parser called Path.read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", forbid_whole_read)
    emitted: list[dict] = []
    rows, ok, errors = parser(path, "HOST", emit=emitted.append)
    assert rows == []
    assert emitted == expected
    assert (ok, errors) == (expected_ok, expected_errors)
    assert ok == len(emitted)


@pytest.mark.parametrize(
    "module, parser, line",
    [
        (syslog, syslog.parse_syslog_file, "Jan  1 01:02:03 host sshd[1]: hello"),
        (auditd, auditd.parse_auditd_file, 'type=SYSCALL msg=audit(1704067200.001:1): pid=2 exe="/bin/sh"'),
        (journal, journal.parse_journal_file, '{"MESSAGE":"hello","__REALTIME_TIMESTAMP":"1704067200000000"}'),
        (dblogs, dblogs.parse_mysql_error_file, "2024-01-01T00:00:00.000000Z 0 [Note] ready"),
    ],
)
def test_emit_occurs_before_next_record_is_requested(module, parser, line, monkeypatch, tmp_path):
    emitted: list[dict] = []

    def lines(path):
        for number in range(20):
            assert len(emitted) == number, "parser buffered earlier rows"
            yield line

    monkeypatch.setattr(module, "iter_text_lines", lines)
    rows, ok, errors = parser(tmp_path / "input.log", "HOST", emit=emitted.append)
    assert (rows, ok, errors) == ([], 20, 0)


@pytest.mark.parametrize(
    "parser, text",
    [
        (
            dblogs.parse_mysql_slow_file,
            "# Time: 2024-01-01T00:00:00.000001Z\nSELECT 1;\n"
            "# Time: 2024-01-01T00:01:00.000001Z\n" + "SELECT 12345;\n" * 5,
        ),
        (
            dblogs.parse_oracle_alert_file,
            "2024-01-01T00:00:00.000001+00:00\nready\n"
            "2024-01-01T00:01:00.000001+00:00\n" + "long message\n" * 5,
        ),
    ],
)
def test_database_logical_record_limit_preserves_only_completed_records(parser, text, tmp_path, monkeypatch):
    path = tmp_path / "database.log"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(dblogs, "_MAX_LOGICAL_RECORD_CHARS", 40)
    emitted: list[dict] = []
    with pytest.raises(ValueError, match="logical record exceeds.*not truncated"):
        parser(path, "HOST", emit=emitted.append)
    assert len(emitted) == 1
    assert emitted[0]["message"] in {"SELECT 1;", "ready"}
    assert path.read_text(encoding="utf-8") == text


def test_oracle_continuation_limit_raises_instead_of_emitting_truncated_row(tmp_path, monkeypatch):
    path = tmp_path / "alert.log"
    path.write_text("2024-01-01T00:00:00.000001+00:00\none\ntwo\nthree\n", encoding="utf-8")
    monkeypatch.setattr(dblogs, "_ORACLE_MAX_CONTINUATION_LINES", 2)
    emitted: list[dict] = []
    with pytest.raises(ValueError, match="2 lines.*not truncated"):
        dblogs.parse_oracle_alert_file(path, "HOST", emit=emitted.append)
    assert emitted == []


def test_qcloud_long_continuation_is_joined_and_enriched_once(tmp_path, monkeypatch):
    path = tmp_path / "vul_scan.log"
    first = "[2026-09-04 00:00:00] [INFO] Execute Command (uid: 0, gid: 0): whoami"
    tail = [f"output {i}" for i in range(1000)]
    path.write_text("\n".join([first, *tail]) + "\n", encoding="utf-8")
    enrich = qcloud._enrich
    calls = []

    def counted_enrich(row):
        calls.append(row["message"])
        enrich(row)

    monkeypatch.setattr(qcloud, "_enrich", counted_enrich)
    emitted: list[dict] = []
    assert qcloud.stream_qcloud_scanner_file(path, "HOST", emitted.append) == (1, 0)
    assert len(calls) == 1
    assert emitted[0]["raw_line"] == "\n".join([first, *tail])
    assert emitted[0]["message"].endswith("\noutput 999")
    assert emitted[0]["event_type"] == "command_execution"
    assert json.loads(emitted[0]["extra"])["command"] == "whoami"


@pytest.mark.parametrize("limit_name, limit, tail", [
    ("_MAX_LOGICAL_RECORD_CHARS", 100, ["x" * 80]),
    ("_MAX_LOGICAL_RECORD_LINES", 2, ["one", "two"]),
])
def test_qcloud_limit_never_emits_truncated_record(limit_name, limit, tail, tmp_path, monkeypatch):
    path = tmp_path / "vul_scan.log"
    first = "[2026-09-04 00:00:00] [INFO] complete"
    pending = "[2026-09-04 00:01:00] [INFO] incomplete"
    path.write_text("\n".join([first, pending, *tail]) + "\n", encoding="utf-8")
    monkeypatch.setattr(qcloud, limit_name, limit)
    emitted: list[dict] = []
    with pytest.raises(ValueError, match="QCloud logical record exceeds.*not truncated"):
        qcloud.stream_qcloud_scanner_file(path, "HOST", emitted.append)
    assert len(emitted) == 1
    assert emitted[0]["message"] == "complete"


class _BoundedReadFile:
    def __init__(self, source):
        self.source = source

    def read(self, size=-1):
        assert size >= 0, "registry parser copied the whole hive"
        return self.source.read(size)

    def __getattr__(self, name):
        return getattr(self.source, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.source.close()


@pytest.mark.parametrize("fail_emit", [False, True])
def test_registry_uses_seekable_file_and_closes_it(tmp_path, monkeypatch, fail_emit):
    path = tmp_path / "SOFTWARE"
    path.write_bytes(build_hive("\\System32\\Config\\SOFTWARE"))
    original_open = Path.open
    sources = []

    def checked_open(self, *args, **kwargs):
        source = original_open(self, *args, **kwargs)
        if self == path and args == ("rb",):
            sources.append(source)
            return _BoundedReadFile(source)
        return source

    emitted = []

    def emit(row):
        if fail_emit:
            raise RuntimeError("writer failed")
        emitted.append(row)

    monkeypatch.setattr(Path, "open", checked_open)
    if fail_emit:
        with pytest.raises(RuntimeError, match="writer failed"):
            registry.parse_registry_hive_file(path, "HOST", emit=emit)
    else:
        assert registry.parse_registry_hive_file(path, "HOST", emit=emit) == ([], 8, 0)
        assert len(emitted) == 8
    assert len(sources) == 1
    assert sources[0].closed


@pytest.mark.parametrize("fail_emit", [False, True])
def test_registry_recovered_hive_is_streamed_and_cleaned_up(tmp_path, monkeypatch, fail_emit):
    path = tmp_path / "SOFTWARE"
    path.write_bytes(build_hive("\\System32\\Config\\SOFTWARE"))
    (tmp_path / "SOFTWARE.LOG1").write_bytes(b"transaction log placeholder")
    restored_paths = []

    def recover(source, log1, *, secondary_log_path, restored_hive_path):
        restored = Path(restored_hive_path)
        restored.write_bytes(build_hive("\\System32\\Config\\SOFTWARE"))
        restored_paths.append(restored)

    monkeypatch.setattr(registry, "apply_transaction_logs", recover)
    emitted = []

    def emit(row):
        if fail_emit:
            raise RuntimeError("writer failed")
        emitted.append(row)

    if fail_emit:
        with pytest.raises(RuntimeError, match="writer failed"):
            registry.parse_registry_hive_file(path, "HOST", emit=emit)
    else:
        assert registry.parse_registry_hive_file(path, "HOST", emit=emit) == ([], 8, 0)
        assert all(row["transaction_log_applied"] for row in emitted)
    assert len(restored_paths) == 1
    assert not restored_paths[0].exists()


def _hive_with_short_iterator(damage: str) -> bytes:
    blob = bytearray(build_hive("\\System32\\Config\\SOFTWARE"))
    if damage in {"first_value", "second_value"}:
        offset = blob.index(b"vk")
        if damage == "second_value":
            offset = blob.index(b"vk", offset + 2)
        # regipy logs the invalid VK signature and returns from iter_values
        # without raising, despite the owning key declaring two values.
        blob[offset:offset + 2] = b"zz"
    else:
        with BytesIO(blob) as source:
            hive = registry._FileBackedRegistryHive(source)
            leaf_offset = REGF_HEADER_SIZE + 4 + hive.root.header.subkeys_list_offset
        assert blob[leaf_offset:leaf_offset + 2] == b"li"
        # The root still declares four children; its index now lists three.
        blob[leaf_offset + 2:leaf_offset + 4] = (3).to_bytes(2, "little")
    return bytes(blob)


@pytest.mark.parametrize("damage", ["first_value", "second_value", "subkeys"])
def test_registry_detects_short_iterators_and_retains_recovered_rows(tmp_path, damage):
    path = tmp_path / "SOFTWARE"
    path.write_bytes(_hive_with_short_iterator(damage))
    emitted = []
    rows, ok, errors = registry.parse_registry_hive_file(path, "HOST", emit=emitted.append)
    assert rows == []
    assert ok == len(emitted) == 7
    assert errors == 1
    by_key = {(row["key_path"], row["value_name"]): row for row in emitted}
    assert ("\\Services\\TestSvc", "ImagePath") in by_key
    if damage == "second_value":
        assert ("\\CurrentVersion\\Run", "Updater") in by_key
        assert ("\\CurrentVersion\\Run", "Payload") not in by_key


@pytest.mark.parametrize("damage", ["first_value", "second_value", "subkeys"])
def test_registry_short_iterator_is_reported_as_partial_by_staging(tmp_path, damage):
    from seclogx.ingest.common import StageStatus
    from seclogx.ingest.logsources.discovery import ClassifiedFile
    from seclogx.ingest.logsources.sniff import KIND_REGISTRY_HIVE
    from seclogx.ingest.logsources.stage import stage_aux_file

    path = tmp_path / "SOFTWARE"
    path.write_bytes(_hive_with_short_iterator(damage))
    source = ClassifiedFile(path=path, host="HOST", size_bytes=path.stat().st_size, kind=KIND_REGISTRY_HIVE)
    report = stage_aux_file(source, tmp_path / "staging")
    assert report.status == StageStatus.PARTIAL
    assert report.record_count == 7
    assert report.error_count == 1
    assert report.error_message


def test_registry_does_not_swallow_regipy_exception_from_emitter():
    def fail_on_value(row):
        if row["value_name"] == "Updater":
            raise RegipyException("writer callback failed")

    with pytest.raises(RegipyException, match="writer callback failed"):
        registry.parse_registry_hive_file(FIXTURES / "registry/SOFTWARE", "HOST", emit=fail_on_value)
