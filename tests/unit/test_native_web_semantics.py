"""Bundled native parser semantics, ownership, and Python compatibility."""
from __future__ import annotations

import gc
import json
import os
import sys

import pyarrow as pa
import pytest

from seclogx import _native_backend as native

from seclogx.ingest.arrow_staging import raw_text
from seclogx.ingest.logsources.parsers.iis import parse_iis_file
from seclogx.ingest.logsources.parsers.webaccess import parse_web_access_file
from seclogx.ingest.logsources.schema import WEB_LOGS_COLUMNS


COLUMNS = [name for name, _ in WEB_LOGS_COLUMNS]
CLF = '127.0.0.1 - alice [10/Oct/2023:13:55:36 +0800] "GET /a?q=1 HTTP/1.1" 200 12 "-" "agent"'


def open_reader(path, kind="web_access", **limits):
    return native.open_web_file(
        str(path), kind, "测试-host", "nginx", str(path), path.name, "a" * 64,
        COLUMNS, max_integer_digits=getattr(sys, "get_int_max_str_digits", lambda: 0)(),
        **limits,
    )


def consume(reader):
    batches, sizes = [], []
    while (item := reader.next_batch()) is not None:
        batch = pa.record_batch(item)
        batch.validate(full=True)
        batches.append(batch)
        sizes.extend(pa.array(item.encoded_record_sizes).to_pylist())
    rows = pa.Table.from_batches(batches).to_pylist() if batches else []
    return rows, sizes


def expected(path, kind):
    if kind == "iis":
        rows, _, errors = parse_iis_file(path, "测试-host")
    else:
        rows, _, errors = parse_web_access_file(path, "测试-host", "nginx")
    sizes = []
    for row in rows:
        row.update(source_path=str(path), source_file=path.name, file_sha256="a" * 64)
        sizes.append(len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1)
    return [{name: raw_text(row.get(name)) for name in COLUMNS} for row in rows], sizes, errors


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
def test_web_splitlines_bom_and_raw_contract(tmp_path, ending):
    path = tmp_path / "nginx.log"
    path.write_bytes(("\ufeff" + ending.join([CLF, "", "not a log", CLF, ""])).encode())
    reader = open_reader(path, max_batch_rows=1)
    rows, sizes = consume(reader)
    want, want_sizes, errors = expected(path, "web_access")
    assert rows == want
    assert sizes == want_sizes
    assert reader.error_count == errors == 1
    assert reader.record_count == 2


@pytest.mark.parametrize("http_request", ["", "-", "GET /x", "GET /x HTTP/1.1", "GET  /x HTTP/1.1", "/x?", "?query", "GET /x?a?b HTTP/1.0"])
@pytest.mark.parametrize("bytes_sent", ["-", "00012", "+12", "1_200", "-12", "-000"])
def test_web_request_and_integer_semantics(tmp_path, http_request, bytes_sent):
    path = tmp_path / "access.log"
    path.write_text(f'host - - [29/Feb/2024:23:59:59 -0330] "{http_request}" 201 {bytes_sent} "-" "-" trailing ignored\n', encoding="utf-8")
    rows, sizes = consume(open_reader(path))
    want, want_sizes, _ = expected(path, "web_access")
    assert (rows, sizes) == (want, want_sizes)


def test_web_unicode_fields_and_json_escaping(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF.replace("alice", "用户").replace("/a?q=1", "/文档?q=😀").replace('"agent"', '"代理\\测试\t"'), encoding="utf-8")
    rows, sizes = consume(open_reader(path))
    want, want_sizes, _ = expected(path, "web_access")
    assert (rows, sizes) == (want, want_sizes)


@pytest.mark.parametrize("timestamp", ["29/Feb/2023:23:59:59 +0000", "31/Apr/2024:10:20:30 +0800", "10/Oct/2023:24:00:00 +0000", "10/Oct/2023:13:55:36 +2400", "10/Oct/2023:13:55:36 -0000"])
def test_web_fixed_time_quirks(tmp_path, timestamp):
    path = tmp_path / "access.log"
    path.write_text(CLF.replace("10/Oct/2023:13:55:36 +0800", timestamp), encoding="utf-8")
    rows, sizes = consume(open_reader(path))
    want, want_sizes, _ = expected(path, "web_access")
    assert (rows, sizes) == (want, want_sizes)


def test_iis_header_changes_duplicate_fields_and_extra(tmp_path):
    path = tmp_path / "iis.log"
    path.write_text(
        "not matching before header\n#Software: Microsoft IIS\n"
        "#Fields: date time c-ip sc-status sc-bytes s-port extra extra cs(User-Agent)\n"
        "2024-02-29 10:20:30 1.2.3.4 0200 1_024 080 first 文档😀 UA\n"
        "2023-02-29 10:20:30 - nope - - first - -\n"
        "wrong field count\n"
        "#Fields: cs-method cs-uri-stem unknown cs-method sc-win32-status\n"
        "GET /x value POST +001\n", encoding="utf-8"
    )
    reader = open_reader(path, "iis", max_batch_rows=1)
    rows, sizes = consume(reader)
    want, want_sizes, errors = expected(path, "iis")
    assert (rows, sizes, reader.error_count) == (want, want_sizes, errors)


@pytest.mark.parametrize("value", ["\x00", "\t", "\b", "\x7f", 'quote"slash\\', "😀文档", "-", ""])
def test_iis_exact_extra_json(tmp_path, value):
    path = tmp_path / "iis.log"
    path.write_text(f"#Fields: c-ip extra\n1.2.3.4 {value}\n", encoding="utf-8")
    rows, sizes = consume(open_reader(path, "iis"))
    want, want_sizes, _ = expected(path, "iis")
    assert (rows, sizes) == (want, want_sizes)


@pytest.mark.parametrize("value", ["\x1f200", "200\x1f", "\t200\t", "+000", "1__2", "_12", "12_", "1_2"])
def test_iis_integer_whitespace_and_underscore_semantics(tmp_path, value):
    path = tmp_path / "iis.log"
    path.write_text(f"#Fields: sc-status\n{value}\n", encoding="utf-8")
    rows, sizes = consume(open_reader(path, "iis"))
    want, want_sizes, _ = expected(path, "iis")
    assert (rows, sizes) == (want, want_sizes)


@pytest.mark.parametrize("digit", ["0", "9"])
def test_iis_current_python_integer_digit_limit(tmp_path, digit):
    limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
    if not limit:
        pytest.skip("this interpreter has no integer digit limit")
    path = tmp_path / "iis.log"
    path.write_text("#Fields: sc-bytes\n" + digit * (limit + 1) + "\n", encoding="utf-8")
    rows, sizes = consume(open_reader(path, "iis"))
    want, want_sizes, _ = expected(path, "iis")
    assert (rows, sizes) == (want, want_sizes)


@pytest.mark.parametrize("timestamp", ["1/Oct/2023:13:55:36 +0000", "10/oct/2023:13:55:36 +0000", "10/Oct/2023:13:55:36 +00:00", "10/Oct/2023:13:55:36 +2460", "10/Oct/2023:13:55:36 x0060", "10/Oct/2023:13:55:36 +0000suffix"])
def test_nonstandard_time_explicitly_requests_full_source_fallback(tmp_path, timestamp):
    path = tmp_path / "access.log"
    path.write_text(CLF + "\n" + CLF.replace("10/Oct/2023:13:55:36 +0800", timestamp), encoding="utf-8")
    reader = open_reader(path, max_batch_rows=1)
    assert pa.record_batch(reader.next_batch()).num_rows == 1
    with pytest.raises(native.UnsupportedInputError):
        reader.next_batch()


def test_unicode_integer_requests_fallback(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF.replace("200 12", "200 １２"), encoding="utf-8")
    with pytest.raises(native.UnsupportedInputError):
        open_reader(path).next_batch()


def test_fatal_integer_returns_prefix_before_error(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF + "\n" + CLF.replace("200 12", "200 bad") + "\n" + CLF, encoding="utf-8")
    reader = open_reader(path)
    batch = pa.record_batch(reader.next_batch())
    assert batch.num_rows == 1
    with pytest.raises(ValueError, match="invalid literal"):
        reader.next_batch()
    assert reader.next_batch() is None


def test_utf8_boundary_crlf_boundary_and_long_line_prefix(tmp_path):
    path = tmp_path / "access.log"
    # Force Unicode and CRLF through internal 64 KiB read boundaries.
    padding = "x" * (65_536 - len(CLF.encode()) - 2)
    path.write_bytes((CLF + padding + "😀\r\n" + CLF).encode())
    rows, sizes = consume(open_reader(path))
    want, want_sizes, _ = expected(path, "web_access")
    assert (rows, sizes) == (want, want_sizes)
    path.write_text(CLF + "\n" + "x" * 256, encoding="utf-8")
    reader = open_reader(path, max_line_chars=200)
    assert pa.record_batch(reader.next_batch()).num_rows == 1
    with pytest.raises(ValueError, match="text line exceeds"):
        reader.next_batch()


def test_encoded_record_limit_returns_prefix(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF + "\n" + CLF.replace('"agent"', '"' + "x" * 2000 + '"'), encoding="utf-8")
    _, sizes, _ = expected(path, "web_access")
    reader = open_reader(path, max_record_bytes=sizes[0])
    item = reader.next_batch()
    assert pa.record_batch(item).num_rows == 1
    assert pa.array(item.encoded_record_sizes).to_pylist() == sizes[:1]
    with pytest.raises(ValueError, match="encoded log record exceeds"):
        reader.next_batch()


def test_batch_bounds_and_owned_buffer_lifetime(tmp_path):
    path = tmp_path / "access.log"
    path.write_text((CLF + "\n") * 20, encoding="utf-8")
    reader = open_reader(path, max_batch_rows=3, max_batch_bytes=2048)
    item = reader.next_batch()
    batch = pa.record_batch(item)
    sizes = pa.array(item.encoded_record_sizes)
    assert 1 <= batch.num_rows <= 3
    assert batch.nbytes <= 2048 or batch.num_rows == 1
    reader.close()
    del item, reader
    gc.collect()
    batch.validate(full=True)
    assert batch.column("host").to_pylist() == ["测试-host"] * batch.num_rows
    assert sizes.null_count == 0


def test_repeated_capsule_exports_have_independent_owners(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF, encoding="utf-8")
    reader = open_reader(path)
    item = reader.next_batch()
    first = pa.record_batch(item)
    second = pa.record_batch(item)
    first_sizes = pa.array(item.encoded_record_sizes)
    second_sizes = pa.array(item.encoded_record_sizes)
    # Unconsumed wrappers must release independently of consumed wrappers.
    unused = item.__arrow_c_array__()
    del unused, item
    reader.close()
    del reader, first, first_sizes
    gc.collect()
    second.validate(full=True)
    assert second.column("client_ip").to_pylist() == ["127.0.0.1"]
    assert second_sizes.to_pylist()[0] > 0


def test_verified_source_handle_is_cloned(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF, encoding="utf-8")
    with path.open("rb") as source:
        if os.name == "nt":
            import msvcrt
            handle = msvcrt.get_osfhandle(source.fileno())
        else:
            handle = source.fileno()
        reader = open_reader(path, source_handle=handle)
        assert pa.record_batch(reader.next_batch()).num_rows == 1
        reader.close()
        os.fstat(source.fileno())
        source.seek(0)
        assert source.read(1)


def test_schema_version_mismatch_rejected_before_reading(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(CLF, encoding="utf-8")
    with pytest.raises(native.UnsupportedInputError, match="schema"):
        native.open_web_file(str(path), "web_access", "host", "nginx", str(path), path.name, "a" * 64, COLUMNS[::-1])


def test_invalid_only_input_returns_bounded_empty_batches(tmp_path):
    path = tmp_path / "access.log"
    path.write_text("not a log\n" * 20, encoding="utf-8")
    reader = open_reader(path, max_batch_rows=3)
    batch = pa.record_batch(reader.next_batch())
    assert batch.num_rows == 0
    assert reader.error_count == 3
    consume(reader)
    assert reader.error_count == 20
