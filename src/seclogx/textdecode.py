"""Shared best-effort bytes -> str decoding for forensic/analyst-supplied
text content of unknown origin (log files, Sigma rule YAML, etc.).

Used anywhere seclogx reads a text file that didn't come from us -- so a
file in an unexpected encoding is read as best-effort text rather than
crashing the caller. See docs/known_limitations.md for the "best-effort
guess, not real charset detection" caveat this implies.
"""

from __future__ import annotations

# Trial order: UTF-8 (with BOM), UTF-16 (with BOM), then GB18030 -- a
# strict superset of GBK/GB2312, covering Simplified/Traditional
# Chinese-locale content -- before falling back to Latin-1 with
# errors="replace", which maps every byte 1:1 and therefore can never
# raise. GB18030 is a Python stdlib codec (`encodings.gb18030`), so this
# adds no new dependency.
_TRIAL_ENCODINGS = ("utf-8-sig", "utf-16", "gb18030")


def decode_text(raw: bytes) -> str:
    for encoding in _TRIAL_ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("latin-1", errors="replace")
