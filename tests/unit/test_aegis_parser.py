"""Aegis format, streaming and public API tests using synthetic evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from seclogx import Case, SourceSpec
from seclogx.ingest.logsources.parsers import aegis
from seclogx.ingest.logsources.sniff import classify_file
from seclogx.ingest.resources import IngestOptions


FIXTURES = Path(__file__).parents[1] / "fixtures" / "aegis"
EXPECTED = {
    "AliSecCheck/data/detect/log/data.4": ("aegis_core", "detect", "AliSecCheck", 3),
    "AliSecCheck/data/rtap/log/data.3": ("aegis_core", "rtap", "AliSecCheck", 2),
    "globalcfg/AliHips/log/data.4": ("aegis_core", "hips", "AliHips", 2),
    "AliSecCheck/data/debug_hips.log": ("aegis_python", "hips_debug", "AliSecCheck", 2),
    "data/atd_lnx_reverse_shell.log": ("aegis_python", "reverse_shell", "aegis", 1),
    "PythonLoader/data/linux-sysinfoext-check.log": ("aegis_python", "python_loader", "PythonLoader", 2),
    "AliSecCheckTmp/data/detect/log/data.4": ("aegis_core", "detect", "AliSecCheckTmp", 1),
    "AliSecCheckTmp/data/rtap/log/data.4": ("aegis_core", "rtap", "AliSecCheckTmp", 1),
    "AliSecCheckTmp/data/tcp-connect-check.log": ("aegis_python", "security_check", "AliSecCheckTmp", 1),
    "AliSecCheck/data/alidetect_config.log": ("aegis_core", "security_check", "AliSecCheck", 1),
}


def make_log(tmp_path, text, relative="AliSecCheck/data/detect/log/data.4", encoding="utf-8"):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode(encoding))
    return path


@pytest.mark.parametrize("relative,expected", EXPECTED.items())
def test_supported_paths_and_all_raw_text_preserved(relative, expected):
    path = FIXTURES / relative
    kind, log_type, component, count = expected
    assert classify_file(path) == kind
    rows, ok, errors = aegis.parse_aegis_core_file(path, "SYNTHETIC")
    assert (ok, errors) == (count, 0)
    assert {row["log_type"] for row in rows} == {log_type}
    assert {row["component"] for row in rows} == {component}
    assert "".join(row["raw_line"] for row in rows) == path.read_bytes().decode("utf-8")


def test_task_fields_and_unlabelled_context():
    rows, _, _ = aegis.parse_aegis_core_file(FIXTURES / "AliSecCheck/data/detect/log/data.4", "H")
    assert [row["event_type"] for row in rows] == ["task_queued", "task_started", "task_completed"]
    assert {row["task_id"] for row in rows} == {"42"}
    assert rows[0]["task_name"] == "synthetic-check"
    assert json.loads(rows[0]["extra"])["queue_length"] == 1
    assert rows[2]["duration_ms"] == 12
    rows, _, _ = aegis.parse_aegis_core_file(FIXTURES / "AliSecCheck/data/rtap/log/data.3", "H")
    assert rows[0]["context_id"] == "123"
    assert rows[1]["severity"] == "WARN"
    assert rows[0]["event_type"] is None
    rows, _, _ = aegis.parse_aegis_core_file(FIXTURES / "AliSecCheck/data/alidetect_config.log", "H")
    assert rows[0]["context_id"] == "765"


@pytest.mark.parametrize("relative,log_type,component", [
    ("aegis_client/aegis_1_23/data/data.4", "client", "AegisClient"),
    ("aegis_client/aegis_1_23/yun_dun_monitor_log/data.3", "monitor", "AegisClient"),
    ("aegis_update/data/data.3", "update", "AegisUpdate"),
    ("PythonLoader/data/data.123.3", "python_loader", "PythonLoader"),
    ("AliSecCheckTmp/data/data.4", "security_check", "AliSecCheckTmp"),
])
def test_additional_numeric_rotation_paths(tmp_path, relative, log_type, component):
    path = make_log(tmp_path, "2026-01-02 03:04:05 [Info] synthetic\n", relative)
    assert classify_file(path) == "aegis_core"
    rows, ok, errors = aegis.parse_aegis_core_file(path, "H")
    assert (ok, errors) == (1, 0)
    assert rows[0]["log_type"] == log_type
    assert rows[0]["component"] == component


def test_monitor_context_only_header_is_a_distinct_complete_record(tmp_path):
    text = "2026-01-02 03:04:05 [INFO] [99] before\n2026-01-02 03:04:06 [000123] synthetic monitor status\n2026-01-02 03:04:07 [123][Error] after\n"
    path = make_log(tmp_path, text, "aegis_client/aegis_1_23/yun_dun_monitor_log/data.3")
    rows, ok, errors = aegis.parse_aegis_core_file(path, "H")
    assert (ok, errors) == (3, 0)
    assert rows[1]["context_id"] == "000123"
    assert rows[1]["severity"] is None
    assert rows[2]["severity"] == "ERROR"
    assert "".join(row["raw_line"] for row in rows) == text


def test_multiline_json_and_python_repr_are_data():
    rows, _, _ = aegis.parse_aegis_core_file(FIXTURES / "globalcfg/AliHips/log/data.4", "H")
    assert '\n\n  "description"' in rows[0]["raw_line"]
    assert json.loads(rows[0]["extra"])["json_payload"]["enabled"] is True
    rows, _, _ = aegis.parse_aegis_python_file(FIXTURES / "data/atd_lnx_reverse_shell.log", "H")
    assert rows[0]["logger"] == "atd_lnx_reverse_shell.py"
    assert "'synthetic': True" in rows[0]["message"]
    assert "json_payload" not in json.loads(rows[0]["extra"])
    assert rows[0]["event_type"] is None  # A detector's diagnostic is not an alert.


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "gb18030", "utf-16"])
def test_encoding_crlf_and_no_final_newline(tmp_path, encoding):
    text = "2026-01-02 03:04:05,123 [alihips-config.py][INFO] 合成测试\r\n\r\n  续行\r\n2026-01-02 03:04:06 [Info] 完成"
    path = make_log(tmp_path, text, "AliSecCheck/data/debug_hips.log", encoding)
    assert classify_file(path) == "aegis_python"
    rows, ok, errors = aegis.parse_aegis_python_file(path, "H")
    assert (ok, errors) == (2, 0)
    assert "".join(row["raw_line"] for row in rows) == text
    assert rows[0]["time_created"].startswith("2026-01-02T03:04:05.123")


@pytest.mark.parametrize("text", [
    "2026-01-02 03:04:05 [Info] ordinary application log\n",
    "2026-01-02 03:04:05 [unknown.py][INFO] ordinary application log\n",
    '{"path": "/usr/local/aegis/", "enabled": true}\n',
])
def test_generic_shape_or_config_is_not_aegis(tmp_path, text):
    path = make_log(tmp_path, text, "unrelated.log")
    assert classify_file(path) is None


@pytest.mark.parametrize("prefix", [b"\x7fELF\x02\x01", b"MZ\x90\x00", b"\x00" * 4096])
def test_binaries_with_embedded_logging_text_are_not_logs(tmp_path, prefix):
    path = make_log(tmp_path, "")
    path.write_bytes(prefix + b"\n2026-01-02 03:04:05 [INFO] /usr/local/aegis/ synthetic\n")
    assert classify_file(path) is None


def test_moved_log_needs_product_evidence_and_cannot_invent_component(tmp_path):
    path = make_log(tmp_path, "2026-01-02 03:04:05 [INFO] ====================Start AliSecCheck : synthetic====================\n", "renamed.txt")
    assert classify_file(path) == "aegis_core"
    rows, _, _ = aegis.parse_aegis_core_file(path, "H")
    assert rows[0]["log_type"] == "agent"
    assert rows[0]["component"] == "aegis"
    path.write_text("2026-01-02 03:04:05 [alihips-config.py][INFO] synthetic\n", encoding="utf-8")
    assert classify_file(path) == "aegis_python"


def test_bad_header_is_reported_and_does_not_pollute_prior_event(tmp_path):
    text = "orphan text\n2026-01-02 03:04:05 [INFO] before\n2026-02-30 03:04:05 [INFO] invalid date\n2026-01-02 broken header\n2026-01-02 03:04:06 [INFO] after"
    path = make_log(tmp_path, text)
    rows, ok, errors = aegis.parse_aegis_core_file(path, "H")
    assert (ok, errors) == (2, 3)
    assert [row["message"] for row in rows] == ["before\n", "after"]


def test_huge_numeric_metadata_does_not_discard_the_log(tmp_path):
    digits = "9" * 5000
    text = f"2026-01-02 03:04:05 [INFO] Add task:synthetic id:{digits} qlen:{digits}\n2026-01-02 03:04:06 [INFO] Task {digits} complete! taken:{digits}ms\n"
    rows, ok, errors = aegis.parse_aegis_core_file(make_log(tmp_path, text), "H")
    assert (ok, errors) == (2, 0)
    assert rows[1]["task_id"] == digits
    assert rows[1]["duration_ms"] is None
    assert "".join(row["raw_line"] for row in rows) == text


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonstandard_json_constants_are_only_raw_text(tmp_path, constant):
    text = f'2026-01-02 03:04:05 [INFO] {{"value": {constant}}}\n'
    rows, _, _ = aegis.parse_aegis_core_file(make_log(tmp_path, text), "H")
    assert "json_payload" not in json.loads(rows[0]["extra"])


@pytest.mark.parametrize("staging_format", ["ndjson", "arrow"])
def test_invalid_json_unicode_does_not_interrupt_ingest(tmp_path, staging_format):
    messages = [
        "before",
        r'{"value":"\ud800"}',
        r'{"\udc00":"value"}',
        r'{"nested":[{"value":"\ud800"}]}',
        r'{"value":"\ud83d\ude00"}',
        "after",
    ]
    text = "".join(f"2026-01-02 03:04:{index:02d} [INFO] {message}\n"
                   for index, message in enumerate(messages))
    path = make_log(tmp_path, text)
    with Case.create("unicode", case_root=tmp_path / "cases") as case:
        report = case.ingest([SourceSpec(path, "H")], workers=1,
                             options=IngestOptions(staging_format=staging_format))
        assert report.aux.files_ok == 1
        assert report.aux.files_partial == report.aux.files_failed == 0
        rows = case.aegis_logs()
        assert len(rows) == len(messages)
        assert "".join(rows["raw_line"]) == text
        extras = [json.loads(extra) for extra in rows["extra"]]
        assert all("json_payload" not in extra for extra in extras[1:4])
        assert extras[4]["json_payload"] == {"value": "\U0001f600"}
        assert case.query("SELECT bool_and(json_valid(extra)) AS valid FROM aegis_logs")["valid"][0]


def test_streaming_does_not_call_collecting_entrypoint(tmp_path, monkeypatch):
    text = "2026-01-02 03:04:05 [INFO] synthetic\n" * 2000
    path = make_log(tmp_path, text)
    def reject(*args, **kwargs):
        raise AssertionError("collecting path must not be used")
    monkeypatch.setattr(aegis, "parse_aegis_core_file", reject)
    count = 0
    def emit(row):
        nonlocal count
        count += 1
    assert aegis.stream_aegis_core_file(path, "H", emit) == (2000, 0)
    assert count == 2000


@pytest.mark.parametrize("bound,value,continuation", [
    ("MAX_AEGIS_RECORD_CHARS", 100, "x" * 70 + "\n"),
    ("MAX_AEGIS_RECORD_LINES", 2, "line one\nline two\n"),
])
def test_record_limit_never_emits_truncated_record(tmp_path, monkeypatch, bound, value, continuation):
    monkeypatch.setattr(aegis, bound, value)
    text = "2026-01-02 03:04:05 [INFO] complete\n2026-01-02 03:04:06 [INFO] oversized\n" + continuation
    path = make_log(tmp_path, text)
    emitted = []
    with pytest.raises(ValueError, match="Aegis event exceeds"):
        aegis.stream_aegis_core_file(path, "H", emitted.append)
    assert len(emitted) == 1
    assert emitted[0]["message"] == "complete\n"


def test_emitter_failure_propagates(tmp_path):
    path = make_log(tmp_path, "2026-01-02 03:04:05 [INFO] synthetic\n")
    def broken_sink(row):
        raise OSError("synthetic full disk")
    with pytest.raises(OSError, match="full disk"):
        aegis.stream_aegis_core_file(path, "H", broken_sink)


@pytest.mark.parametrize("staging_format", ["ndjson", "arrow"])
def test_public_ingest_query_provenance_and_idempotency(tmp_path, staging_format):
    with Case.create("aegis", case_root=tmp_path / "cases") as case:
        sources = [SourceSpec(FIXTURES, "SYNTHETIC")]
        result = case.ingest(sources, workers=1, options=IngestOptions(staging_format=staging_format))
        assert result.aux.files_ok == 10
        assert result.aux.files_partial == result.aux.files_failed == result.aux.files_unknown == 0
        assert result.aux.rows_written == {"aegis_logs": 16}
        rows = case.aegis_logs()
        assert len(rows) == 16
        assert len(case.aegis_logs(log_type="detect")) == 4
        assert sum(len(chunk) for chunk in case.aegis_logs_chunks(chunksize=3)) == 16
        assert len(case.search("aegis_logs", eq={"event_type": "task_completed"})) == 1
        for relative in EXPECTED:
            path = FIXTURES / relative
            subset = rows.loc[rows["source_path"] == str(path)]
            assert not subset.empty
            assert set(subset["file_sha256"]) == {hashlib.sha256(path.read_bytes()).hexdigest()}
        again = case.ingest(sources, workers=1)
        assert len(again.already_imported) == 10
        assert len(case.aegis_logs()) == 16


def test_accessors_on_case_without_aegis_logs(tmp_path):
    with Case.create("empty", case_root=tmp_path / "cases") as case:
        assert case.aegis_logs().empty
        assert case.aegis_logs(log_type="hips").empty
        assert list(case.aegis_logs_chunks()) == []
