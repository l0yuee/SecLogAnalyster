from pathlib import Path

import pytest

from seclogx.ingest.logsources.sniff import classify_file, KIND_WEB_ACCESS, KIND_SCHEDULED_TASK
from seclogx.textdecode import decode_text, prepare_text, iter_text_lines, use_prepared_text


LINE = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /中文 HTTP/1.0" 200 123\n'


@pytest.mark.parametrize("large", [False, True])
@pytest.mark.parametrize("parity", [0, 1])
def test_gbk_classification_and_preparation_do_not_depend_on_byte_parity(tmp_path, large, parity):
    text = LINE * (400 if large else 1)
    raw = text.encode("gbk")
    if len(raw) % 2 != parity:
        raw += b" "
        text += " "
    path = tmp_path / "access.log"
    path.write_bytes(raw)
    assert classify_file(path) == KIND_WEB_ACCESS
    prepared = prepare_text(path)
    assert prepared.encoding == "gb18030"
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path)) == text.splitlines()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-8-sig", "gb18030"])
def test_encoded_web_log_detected_and_read_consistently(tmp_path, encoding):
    path = tmp_path / "access.log"
    path.write_bytes(LINE.encode(encoding))
    assert classify_file(path) == KIND_WEB_ACCESS
    prepared = prepare_text(path)
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path)) == [LINE.rstrip("\n")]


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_ascii_utf16_is_not_mistaken_for_valid_utf8(tmp_path, encoding):
    path = tmp_path / "text.log"
    path.write_bytes("hello world\n".encode(encoding))
    assert prepare_text(path).encoding == encoding
    assert list(iter_text_lines(path)) == ["hello world"]


@pytest.mark.parametrize("encoding", ["utf-8", "gb18030", "utf-16-le", "utf-16-be"])
def test_partial_prefix_can_end_inside_a_character(encoding):
    text = LINE.rstrip("\n") + "中"
    raw = text.encode(encoding)
    assert decode_text(raw[:-1], partial=True) == text[:-1]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_scheduled_task_classified_before_binary_bailout(tmp_path, encoding):
    path = tmp_path / "task"
    path.write_bytes(('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                      '<Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>').encode(encoding))
    assert classify_file(path) == KIND_SCHEDULED_TASK


def test_nul_binary_is_not_promoted_to_utf16_text(tmp_path):
    path = tmp_path / "random.bin"
    path.write_bytes(b"\0" * 16384)
    assert classify_file(path) is None


def test_ingest_recovers_all_gbk_parity_and_prefix_variants(tmp_path):
    from seclogx import Case
    source = tmp_path / "input"
    source.mkdir()
    for count in (1, 400):
        for parity in (0, 1):
            raw = (LINE * count).encode("gbk")
            if len(raw) % 2 != parity:
                raw += b" "
            (source / f"access-{count}-{parity}.log").write_bytes(raw)
    case = Case.create("gbk", case_root=tmp_path / "cases")
    report = case.ingest([str(source)], workers=1)
    assert report.aux.files_ok == 4
    assert report.aux.files_unknown == 0
    assert report.aux.rows_written["web_logs"] == 802
    assert case.query("SELECT count(*) AS n FROM web_logs WHERE uri_stem = '/中文'").iloc[0, 0] == 802
