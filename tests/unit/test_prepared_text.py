"""Hash/encoding preparation is scoped, bounded, and invalidated by changes."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

import seclogx.textdecode as textdecode
from seclogx.textdecode import SourceChangedError, iter_text_lines, prepare_text, use_prepared_text


class _ObservedReader:
    def __init__(self, source, on_read):
        self.source = source
        self.on_read = on_read

    def __getattr__(self, name):
        return getattr(self.source, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self.source.__exit__(*exc)

    def read(self, size=-1):
        data = self.source.read(size)
        self.on_read(size, data)
        return data


def test_utf8_preparation_hashes_and_validates_in_one_bounded_pass(tmp_path, monkeypatch):
    raw = ("\ufeff" + "hello \u4e2d\U0001f642\r\n" * 50).encode("utf-8")
    path = tmp_path / "source.log"
    path.write_bytes(raw)
    original_open = Path.open
    read_sizes = []
    bytes_read = []

    def observed_open(self, mode="r", *args, **kwargs):
        source = original_open(self, mode, *args, **kwargs)
        if self == path and mode == "rb":
            return _ObservedReader(source, lambda size, data: (read_sizes.append(size), bytes_read.append(len(data))))
        return source

    monkeypatch.setattr(Path, "open", observed_open)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 7)
    prepared = prepare_text(path)
    assert prepared.sha256 == hashlib.sha256(raw).hexdigest()
    assert prepared.encoding == "utf-8-sig"
    assert sum(bytes_read) == len(raw)
    assert read_sizes and set(read_sizes) == {7}

    def no_validation(*args, **kwargs):
        raise AssertionError("the matching scope must reuse validated encoding")

    monkeypatch.setattr(textdecode, "_validated_encoding", no_validation)
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path, keepends=True)) == raw.decode("utf-8-sig").splitlines(keepends=True)


def test_descriptor_ctime_can_differ_without_invalidating_stable_source(tmp_path, monkeypatch):
    """Windows path stat and fstat may report different ctime values."""
    path = tmp_path / "stable.log"
    path.write_text("stable source\n", encoding="utf-8")
    original_fstat = os.fstat

    def different_descriptor_ctime(fd):
        stamp = original_fstat(fd)
        return SimpleNamespace(
            st_dev=stamp.st_dev, st_ino=stamp.st_ino, st_size=stamp.st_size,
            st_mtime_ns=stamp.st_mtime_ns, st_ctime_ns=stamp.st_ctime_ns + 1_000_000_000,
        )

    monkeypatch.setattr(textdecode.os, "fstat", different_descriptor_ctime)
    prepared = prepare_text(path)
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path)) == ["stable source"]


@pytest.mark.parametrize("raw,requires_bom", [
    (b"", False),
    ("hello\n\u7528\u6237\r\n".encode("utf-8-sig"), False),
    ("hello\n\u7528\u6237\r\n".encode("utf-16"), False),
    ("\u7528\u6237\u767b\u5f55\u5931\u8d25\r\n".encode("gb18030"), True),
    ("\u7528\u6237\u767b\u5f55\u5931\u8d25\r\n".encode("gb18030"), False),
    (b"valid prefix\n" * 50 + b"\xff\xff\xff", True),
    (b"valid prefix\n" * 50 + b"\xe2\x82", True),
])
def test_preparation_preserves_hash_and_full_encoding_fallback(tmp_path, monkeypatch, raw, requires_bom):
    path = tmp_path / "encoded.log"
    path.write_bytes(raw)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 3)
    expected = list(iter_text_lines(path, utf16_requires_bom=requires_bom))
    prepared = prepare_text(path, utf16_requires_bom=requires_bom)
    assert prepared.sha256 == hashlib.sha256(raw).hexdigest()
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path, utf16_requires_bom=requires_bom)) == expected


@pytest.mark.parametrize("requires_bom", [False, True])
def test_late_invalid_utf8_is_not_validated_twice(tmp_path, monkeypatch, requires_bom):
    raw = b"valid prefix\n" * 128 + b"\xff\xff\xff"
    path = tmp_path / "late-invalid.log"
    path.write_bytes(raw)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 64)
    expected = list(iter_text_lines(path, utf16_requires_bom=requires_bom))
    original_decoder = textdecode.codecs.getincrementaldecoder
    requested_encodings = []
    utf8_bytes = 0

    def observed_decoder(encoding):
        requested_encodings.append(encoding)
        decoder_type = original_decoder(encoding)
        if encoding != "utf-8-sig":
            return decoder_type

        class CountedDecoder(decoder_type):
            def decode(self, data, final=False):
                nonlocal utf8_bytes
                utf8_bytes += len(data)
                return super().decode(data, final=final)

        return CountedDecoder

    monkeypatch.setattr(textdecode.codecs, "getincrementaldecoder", observed_decoder)
    prepared = prepare_text(path, utf16_requires_bom=requires_bom)
    assert requested_encodings.count("utf-8-sig") == 1
    assert utf8_bytes == len(raw)
    assert prepared.sha256 == hashlib.sha256(raw).hexdigest()
    assert prepared.encoding == "latin-1"
    with use_prepared_text(prepared):
        assert list(iter_text_lines(path, utf16_requires_bom=requires_bom)) == expected


def test_prepared_scope_does_not_match_other_paths_or_decoding_policies(tmp_path, monkeypatch):
    path = tmp_path / "legacy.log"
    text = "\u7528\u6237\u767b\u5f55\u5931\u8d25\r\n"
    path.write_bytes(text.encode("gb18030"))
    other = tmp_path / "other.log"
    other.write_text("other\n", encoding="utf-8")
    prepared = prepare_text(path)
    original_validate = textdecode._validated_encoding
    validated = []

    def track_validation(candidate, **kwargs):
        validated.append(Path(candidate))
        return original_validate(candidate, **kwargs)

    monkeypatch.setattr(textdecode, "_validated_encoding", track_validation)
    with use_prepared_text(prepared):
        assert list(iter_text_lines(other)) == ["other"]
        assert list(iter_text_lines(path, utf16_requires_bom=True)) == [text.rstrip("\r\n")]
    assert validated == [other, path]


def test_nested_scope_restores_after_exception_and_does_not_leak(tmp_path, monkeypatch):
    first, second = tmp_path / "first.log", tmp_path / "second.log"
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")
    outer, inner = prepare_text(first), prepare_text(second)
    original_validate = textdecode._validated_encoding
    validated = []

    def track_validation(candidate, **kwargs):
        validated.append(Path(candidate))
        return original_validate(candidate, **kwargs)

    monkeypatch.setattr(textdecode, "_validated_encoding", track_validation)
    with use_prepared_text(outer):
        with pytest.raises(LookupError, match="parser failed"):
            with use_prepared_text(inner):
                assert list(iter_text_lines(second)) == ["second"]
                raise LookupError("parser failed")
        assert list(iter_text_lines(first)) == ["first"]
        assert validated == []
    assert list(iter_text_lines(first)) == ["first"]
    assert validated == [first]


def test_prepared_scope_is_not_a_shared_worker_thread_cache(tmp_path, monkeypatch):
    path = tmp_path / "source.log"
    path.write_text("source\n", encoding="utf-8")
    prepared = prepare_text(path)
    original_validate = textdecode._validated_encoding
    validated = []

    def track_validation(candidate, **kwargs):
        validated.append(Path(candidate))
        return original_validate(candidate, **kwargs)

    monkeypatch.setattr(textdecode, "_validated_encoding", track_validation)
    with use_prepared_text(prepared):
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(lambda: list(iter_text_lines(path))).result() == ["source"]
        assert list(iter_text_lines(path)) == ["source"]
    assert validated == [path]


def test_modified_source_cannot_enter_prepared_scope(tmp_path):
    path = tmp_path / "source.log"
    path.write_text("original\n", encoding="utf-8")
    prepared = prepare_text(path)
    path.write_text("changed source\n", encoding="utf-8")
    with pytest.raises(SourceChangedError, match="changed"):
        with use_prepared_text(prepared):
            pytest.fail("a stale preparation was accepted")


def test_modified_source_is_checked_again_before_iteration(tmp_path):
    path = tmp_path / "source.log"
    path.write_text("original\n", encoding="utf-8")
    prepared = prepare_text(path)
    with pytest.raises(SourceChangedError, match="changed"):
        with use_prepared_text(prepared):
            path.write_text("changed source\n", encoding="utf-8")
            next(iter_text_lines(path))


def test_source_changed_during_iteration_is_not_reported_as_success(tmp_path):
    path = tmp_path / "source.log"
    path.write_text("first\nsecond\n", encoding="utf-8")
    prepared = prepare_text(path)
    with pytest.raises(SourceChangedError, match="changed"):
        with use_prepared_text(prepared):
            lines = iter_text_lines(path)
            assert next(lines) == "first"
            stamp = path.stat()
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 2_000_000_000))
            list(lines)


def test_source_changed_during_preparation_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "source.log"
    path.write_text("a long enough source to need several reads\n", encoding="utf-8")
    original_open = Path.open
    changed = False

    def on_read(size, data):
        nonlocal changed
        if data and not changed:
            stamp = path.stat()
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 2_000_000_000))
            changed = True

    def observed_open(self, mode="r", *args, **kwargs):
        source = original_open(self, mode, *args, **kwargs)
        return _ObservedReader(source, on_read) if self == path and mode == "rb" else source

    monkeypatch.setattr(Path, "open", observed_open)
    monkeypatch.setattr(textdecode, "_DECODE_CHUNK_SIZE", 7)
    with pytest.raises(SourceChangedError, match="changed"):
        prepare_text(path)
