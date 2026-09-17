"""Shared best-effort bytes -> str decoding for forensic/analyst-supplied
text content of unknown origin (log files, Sigma rule YAML, etc.).

Used anywhere seclogx reads a text file that didn't come from us -- so a
file in an unexpected encoding is read as best-effort text rather than
crashing the caller. See docs/known_limitations.md for the "best-effort
guess, not real charset detection" caveat this implies.
"""

from __future__ import annotations

import codecs
import hashlib
import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, TextIO

# Trial order: UTF-8 (with BOM), UTF-16 (with BOM), then GB18030 -- a
# strict superset of GBK/GB2312, covering Simplified/Traditional
# Chinese-locale content -- before falling back to Latin-1 with
# errors="replace", which maps every byte 1:1 and therefore can never
# raise. GB18030 is a Python stdlib codec (`encodings.gb18030`), so this
# adds no new dependency.
_TRIAL_ENCODINGS = ("utf-8-sig", "utf-16", "gb18030")
_DECODE_CHUNK_SIZE = 64 * 1024
MAX_TEXT_RECORD_CHARS = 8 * 1024 * 1024
_LINE_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"


class TextRecordTooLargeError(ValueError):
    """A source record exceeds the explicit bounded-memory parsing limit."""


class SourceChangedError(OSError):
    """A prepared evidence source changed before or during parsing."""


def _stat_signature(stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


@dataclass(frozen=True)
class PreparedText:
    """A hash and validated encoding for one stable path and decoding policy.

    Construct with prepare_text(). File identity, size and nanosecond
    timestamps are checked on reuse; this is not an immutable snapshot.
    """

    path: Path
    sha256: str
    encoding: str
    utf16_requires_bom: bool
    _signature: tuple[int, int, int, int, int] = field(repr=False)


_PREPARED_TEXT: ContextVar[PreparedText | None] = ContextVar("seclogx_prepared_text", default=None)


def _verify_prepared(prepared: PreparedText, source: TextIO | None = None) -> None:
    try:
        signature = _stat_signature(prepared.path.stat())
        handle_signature = _stat_signature(os.fstat(source.fileno())) if source is not None else signature
    except OSError as exc:
        raise SourceChangedError(f"prepared text source is no longer accessible: {prepared.path}") from exc
    # On Windows, stat(path).st_ctime and fstat(fd).st_ctime can describe
    # different timestamps. Compare ctime path-to-path only; descriptor
    # identity, size and mtime must still match the prepared source.
    if signature != prepared._signature or handle_signature[:4] != prepared._signature[:4]:
        raise SourceChangedError(f"prepared text source changed: {prepared.path}")


def prepare_text(path: Path, *, utf16_requires_bom: bool = False) -> PreparedText:
    """Hash and strictly validate ordinary UTF-8 in one bounded file pass.

    If UTF-8 is invalid, finish hashing every source byte, then use the
    existing full-file fallback sequence. No parser records are emitted
    during preparation, including when invalid bytes occur near EOF.
    """
    path = Path(path).resolve()
    signature = _stat_signature(path.stat())
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8-sig")(errors="strict")
    utf8_valid = True
    with path.open("rb") as source:
        if _stat_signature(os.fstat(source.fileno()))[:4] != signature[:4]:
            raise SourceChangedError(f"text source changed before preparing: {path}")
        while chunk := source.read(_DECODE_CHUNK_SIZE):
            digest.update(chunk)
            if utf8_valid:
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeError:
                    utf8_valid = False
        if utf8_valid:
            try:
                decoder.decode(b"", final=True)
            except UnicodeError:
                utf8_valid = False
        if _stat_signature(os.fstat(source.fileno()))[:4] != signature[:4]:
            raise SourceChangedError(f"text source changed while preparing: {path}")
    encoding = "utf-8-sig" if utf8_valid else _validated_encoding(
        path, utf16_requires_bom=utf16_requires_bom, skip_utf8=True,
    )
    prepared = PreparedText(path, digest.hexdigest(), encoding, utf16_requires_bom, signature)
    _verify_prepared(prepared)
    return prepared


@contextmanager
def use_prepared_text(prepared: PreparedText) -> Iterator[PreparedText]:
    """Reuse preparation only inside this execution context, restoring on exit.

    Nested scopes restore the previous source. Unrelated paths or decoding
    policies still validate normally; worker threads do not share a global
    cache. A normal scope exit checks that the source is still unchanged.
    """
    _verify_prepared(prepared)
    token = _PREPARED_TEXT.set(prepared)
    try:
        yield prepared
        _verify_prepared(prepared)
    finally:
        _PREPARED_TEXT.reset(token)


@contextmanager
def _open_text(path: Path, encoding: str, prepared: PreparedText | None) -> Iterator[TextIO]:
    with path.open("r", encoding=encoding, errors="strict", newline="") as source:
        if prepared is not None:
            _verify_prepared(prepared, source)
        try:
            yield source
        finally:
            if prepared is not None:
                _verify_prepared(prepared, source)


def decode_text(raw: bytes) -> str:
    for encoding in _TRIAL_ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _validated_encoding(
    path: Path, *, utf16_requires_bom: bool = False, skip_utf8: bool = False,
) -> str:
    """Validate before yielding anything, including errors after a valid prefix.

    Re-reading the selected encoding costs one sequential pass, but avoids
    emitting a prefix in one encoding and then duplicating it on fallback.
    The BOM-less UTF-16 codec mirrors bytes.decode('utf-16')'s native order.
    Preparation can skip UTF-8 only after its hash pass has rejected it.
    """
    with path.open("rb") as source:
        prefix = source.read(2)
        has_utf16_bom = prefix in (b"\xff\xfe", b"\xfe\xff")
        utf16 = "utf-16" if has_utf16_bom else (
            "utf-16-le" if sys.byteorder == "little" else "utf-16-be"
        )
        candidates = ("utf-8-sig", utf16, "gb18030") if (
            has_utf16_bom or not utf16_requires_bom
        ) else ("utf-8-sig", "gb18030")
        if skip_utf8:
            candidates = candidates[1:]
        for encoding in candidates:
            source.seek(0)
            decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
            try:
                while chunk := source.read(_DECODE_CHUNK_SIZE):
                    decoder.decode(chunk, final=False)
                decoder.decode(b"", final=True)
            except UnicodeError:
                continue
            return encoding
    return "latin-1"


def iter_text_lines(
    path: Path, *, keepends: bool = False, max_line_chars: int = MAX_TEXT_RECORD_CHARS,
    utf16_requires_bom: bool = False,
) -> Iterator[str]:
    """Yield decoded lines using bounded reads and str.splitlines semantics.

    CRLF is kept together even across read boundaries. ``keepends=True``
    preserves original line endings for CSV fields that span physical lines.
    A physical line larger than the limit raises rather than being truncated.
    Encoding fallback is strict and validated over the whole file first;
    source changes during the second pass are never silently replaced.
    Set ``utf16_requires_bom`` for formats whose legacy encoding detection
    only chose UTF-16 when a BOM was present (notably Tencent client logs).
    """
    if max_line_chars < 1:
        raise ValueError("max_line_chars must be positive")
    path = Path(path)
    prepared = _PREPARED_TEXT.get()
    if prepared is not None and (
        prepared.utf16_requires_bom == utf16_requires_bom and prepared.path == path.resolve()
    ):
        _verify_prepared(prepared)
        encoding = prepared.encoding
    else:
        prepared = None
        encoding = _validated_encoding(path, utf16_requires_bom=utf16_requires_bom)
    parts: list[str] = []
    length = 0
    carry_cr = ""
    with _open_text(path, encoding, prepared) as source:
        while True:
            chunk = source.read(_DECODE_CHUNK_SIZE)
            eof = not chunk
            chunk = carry_cr + chunk
            carry_cr = ""
            if not eof and chunk.endswith("\r"):
                chunk, carry_cr = chunk[:-1], "\r"
            # str.splitlines scans in C and creates no per-line regex Match.
            # Most records fit wholly within a read chunk, so only its first
            # and last records need the cross-chunk accumulation machinery.
            lines = chunk.splitlines(keepends=keepends)
            tail = lines.pop() if chunk and chunk[-1] not in _LINE_BREAKS else ""
            if parts and lines:
                first = lines[0]
                ending = (2 if first.endswith("\r\n") else 1) if keepends else 0
                if length + len(first) - ending > max_line_chars:
                    raise TextRecordTooLargeError(f"text line exceeds {max_line_chars} characters: {path}")
                parts.append(first)
                lines[0] = "".join(parts)
                parts.clear()
                length = 0

            # Complete lines taken from one chunk cannot exceed that chunk.
            # The default limit is larger than a read, so the hot path can
            # yield directly. A joined cross-chunk first line was checked
            # above; custom smaller limits still validate every full line.
            if max_line_chars < len(chunk):
                for line in lines:
                    ending = (2 if line.endswith("\r\n") else 1) if keepends else 0
                    if len(line) - ending > max_line_chars:
                        raise TextRecordTooLargeError(f"text line exceeds {max_line_chars} characters: {path}")
                    yield line
            else:
                yield from lines
            if tail:
                parts.append(tail)
                length += len(tail)
                if length > max_line_chars:
                    raise TextRecordTooLargeError(f"text line exceeds {max_line_chars} characters: {path}")
            if eof:
                if parts:
                    yield "".join(parts)
                break
