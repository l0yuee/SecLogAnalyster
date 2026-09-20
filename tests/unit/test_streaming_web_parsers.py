"""Streaming emits completed records and preserves the collecting API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import seclogx.textdecode as textdecode
from seclogx.ingest.logsources.parsers import exchange, weberror
from seclogx.ingest.logsources.parsers._stream import RowSink
from seclogx.ingest.logsources.parsers.exchange import parse_exchange_csv
from seclogx.ingest.logsources.parsers.iis import parse_iis_file
from seclogx.ingest.logsources.parsers.webaccess import parse_web_access_file
from seclogx.ingest.logsources.parsers.weberror import (
    parse_apache_error_file, parse_iis_httperr_file, parse_nginx_error_file, parse_tomcat_error_file,
)
from seclogx.textdecode import TextRecordTooLargeError, decode_text, iter_text_lines

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources"


@pytest.mark.parametrize("parser,fixture,kwargs", [
    (parse_iis_file, "sample_iis.log", {}),
    (parse_web_access_file, "sample_nginx_access.log", {"log_type": "nginx"}),
    (parse_nginx_error_file, "sample_nginx_error.log", {}),
    (parse_apache_error_file, "sample_apache_error.log", {}),
    (parse_tomcat_error_file, "sample_tomcat_error.log", {}),
    (parse_iis_httperr_file, "sample_iis_httperr.log", {}),
    (parse_exchange_csv, "sample_message_tracking.csv", {"subkind": "exchange_message_tracking"}),
    (parse_exchange_csv, "sample_httpproxy.csv", {"subkind": "exchange_generic"}),
])
def test_streaming_matches_collecting_without_whole_file_reads(parser, fixture, kwargs, monkeypatch):
    path = FIXTURES / fixture
    expected = parser(path, "HOST", **kwargs)

    def reject_read_bytes(self):
        raise AssertionError("streaming parser must not read the entire file")

    monkeypatch.setattr(Path, "read_bytes", reject_read_bytes)
    emitted = []
    # Copy at emission, just as staging serializes immediately: catches
    # prematurely emitted Tomcat rows whose continuation is added later.
    result = parser(path, "HOST", emit=lambda row: emitted.append(dict(row)), **kwargs)
    assert emitted == expected[-3]
    assert result[-3] == []
    assert result[-2:] == expected[-2:]
    if parser is parse_exchange_csv:
        assert result[0] == expected[0]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "gb18030", "latin-1"])
def test_streaming_decode_matches_existing_fallback_and_line_endings(tmp_path, monkeypatch, encoding):
    text = "first\r\nsecond\rthird\nfourth\vlast\u0085" + ("caf\u00e9" if encoding == "latin-1" else "\u7528\u6237")
    raw = text.encode(encoding)
    path = tmp_path / "encoded.log"
    path.write_bytes(raw)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 3)
    expected = decode_text(raw)
    assert list(iter_text_lines(path)) == expected.splitlines()
    assert list(iter_text_lines(path, keepends=True)) == expected.splitlines(keepends=True)


@pytest.mark.parametrize("text", ["", "\n", "a\r", "a\r\n", "a\r\nb\n\n", "a\x1cb\x1dc\x1e"])
def test_streaming_line_boundaries_match_splitlines(tmp_path, monkeypatch, text):
    path = tmp_path / "lines.log"
    path.write_bytes(text.encode())
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 1)
    assert list(iter_text_lines(path)) == text.splitlines()
    assert list(iter_text_lines(path, keepends=True)) == text.splitlines(keepends=True)


def test_late_encoding_failure_is_validated_before_first_line(tmp_path, monkeypatch):
    # Odd byte length rejects BOM-less UTF-16; invalid GB18030 tail forces
    # Latin-1. The first line must not be emitted once for each attempted codec.
    raw = b"first\n" * 100 + b"\xff\xff\xff"
    path = tmp_path / "late-failure.log"
    path.write_bytes(raw)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 7)
    assert list(iter_text_lines(path)) == decode_text(raw).splitlines()


@pytest.mark.parametrize("encoding", ["gb18030", "utf-16", "utf-8"])
def test_bom_required_encoding_mode_preserves_chinese_text(tmp_path, encoding):
    # Even-length GB18030 can be valid BOM-less UTF-16 but mean something
    # entirely different. QCloud historically required a UTF-16 BOM.
    text = "\u7528\u6237\u767b\u5f55\u5931\u8d25\r\n"
    path = tmp_path / "qcloud-encoding.log"
    path.write_bytes(text.encode(encoding))
    assert list(iter_text_lines(path, utf16_requires_bom=True)) == [text.rstrip("\r\n")]


def test_oversized_physical_line_raises_without_truncation(tmp_path, monkeypatch):
    path = tmp_path / "large-line.log"
    path.write_bytes(b"ok\n" + b"x" * 30)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 4)
    lines = iter_text_lines(path, max_line_chars=12)
    assert next(lines) == "ok"
    with pytest.raises(TextRecordTooLargeError, match="exceeds 12"):
        next(lines)


def test_every_splitlines_separator_at_different_chunk_boundaries(tmp_path, monkeypatch):
    separators = ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
    text = "".join(separator + "ab\u4e2d\U0001f642" + separator for separator in separators) + "tail"
    path = tmp_path / "all-line-breaks.log"
    path.write_bytes(text.encode("utf-8"))
    for chunk_size in (1, 2, 3, 7, 31, 64):
        monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", chunk_size)
        for keepends in (False, True):
            assert list(iter_text_lines(path, keepends=keepends)) == text.splitlines(keepends=keepends)


@pytest.mark.parametrize("keepends", [False, True])
@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r", "\u2028"])
def test_cross_chunk_line_limit_excludes_terminator(tmp_path, monkeypatch, keepends, ending):
    path = tmp_path / "line-limit.log"
    text = "x" * 35 + ending + "ok" + ending + "y" * 36 + ending
    path.write_bytes(text.encode("utf-8"))
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 7)
    lines = iter_text_lines(path, max_line_chars=35, keepends=keepends)
    assert next(lines) == "x" * 35 + (ending if keepends else "")
    assert next(lines) == "ok" + (ending if keepends else "")
    with pytest.raises(TextRecordTooLargeError, match="exceeds 35"):
        next(lines)


def test_long_line_crosses_default_read_chunks(tmp_path):
    path = tmp_path / "cross-chunk.log"
    text = "before\n" + "x" * (textdecode._DECODE_CHUNK_SIZE * 2 + 3) + "\r\nafter"
    path.write_bytes(text.encode("utf-8"))
    assert list(iter_text_lines(path)) == text.splitlines()
    assert list(iter_text_lines(path, keepends=True)) == text.splitlines(keepends=True)


def test_exchange_quoted_multiline_preserves_newlines_and_header_like_text(tmp_path):
    path = tmp_path / "exchange.csv"
    path.write_bytes(
        b"#Log-type: HttpProxy\r\n#Fields: date-time,Subject\r\n"
        b'2026-01-01T00:00:00Z,"first\r\n#Fields: part of value\r\nlast"\r\n'
        b'2026-01-01T00:00:01Z,"quote ""inside"""\r\n'
    )
    emitted = []
    table, rows, ok, err = parse_exchange_csv(path, "HOST", "exchange_generic", emit=emitted.append)
    assert (table, rows, ok, err) == ("exchange_logs", [], 2, 0)
    assert json.loads(emitted[0]["fields"])["Subject"] == "first\r\n#Fields: part of value\r\nlast"
    assert json.loads(emitted[1]["fields"])["Subject"] == 'quote "inside"'


def test_exchange_unclosed_quoted_record_is_rejected(tmp_path):
    path = tmp_path / "unclosed.csv"
    path.write_text('#Fields: Subject\n"never\nclosed', encoding="utf-8")
    assert parse_exchange_csv(path, "HOST", "exchange_generic")[-3:] == ([], 0, 1)


def test_exchange_oversized_logical_record_raises(tmp_path, monkeypatch):
    path = tmp_path / "oversized.csv"
    path.write_text('#Fields: Subject\n"' + 'x' * 20 + '\n' + 'y' * 20 + '"\n', encoding="utf-8")
    monkeypatch.setattr(exchange, "MAX_TEXT_RECORD_CHARS", 32)
    with pytest.raises(TextRecordTooLargeError, match="CSV record exceeds 32"):
        parse_exchange_csv(path, "HOST", "exchange_generic", emit=lambda row: None)


def test_tomcat_oversized_logical_record_is_not_emitted(tmp_path, monkeypatch):
    path = tmp_path / "tomcat.log"
    path.write_text("01-Jan-2026 00:00:00.000 SEVERE [main] logger start\n" + "x" * 20 + "\n", encoding="utf-8")
    monkeypatch.setattr(weberror, "MAX_TEXT_RECORD_CHARS", 24)
    emitted = []
    with pytest.raises(TextRecordTooLargeError, match="Tomcat logical record"):
        parse_tomcat_error_file(path, "HOST", emit=emitted.append)
    assert emitted == []


def test_rowsink_does_not_retain_emitted_rows_and_propagates_callback_failure():
    sink = RowSink(lambda row: None)
    for i in range(1000):
        sink.append({"i": i})
    assert sink.rows == []
    assert sink.count == 1000

    def fail(row):
        raise OSError("staging disk full")

    sink = RowSink(fail)
    with pytest.raises(OSError, match="disk full"):
        sink.append({"i": 1})
    assert sink.count == 0


def test_tomcat_continuation_limit_does_not_emit_a_truncated_record(tmp_path):
    path = tmp_path / "tomcat.log"
    path.write_text("01-Jan-2026 00:00:00.000 SEVERE [main] logger start\n"
                    + "stack frame\n" * 201, encoding="utf-8")
    emitted = []
    with pytest.raises(TextRecordTooLargeError, match="200 continuation lines"):
        parse_tomcat_error_file(path, "HOST", emit=emitted.append)
    assert emitted == []
