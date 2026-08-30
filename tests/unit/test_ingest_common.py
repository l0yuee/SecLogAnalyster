from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from seclogx.ingest.common import StageStatus, now_iso, sha256_file


def test_sha256_file_matches_hashlib(tmp_path: Path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"seclogx test content" * 100)

    expected = hashlib.sha256(p.read_bytes()).hexdigest()
    assert sha256_file(p) == expected


def test_sha256_file_respects_chunk_size(tmp_path: Path):
    # A chunk size smaller than the file forces multiple reads through the
    # iter(read, b"") loop -- confirm that path still hashes correctly.
    p = tmp_path / "chunked.bin"
    data = b"0123456789" * 50
    p.write_bytes(data)

    assert sha256_file(p, chunk_size=7) == hashlib.sha256(data).hexdigest()


def test_sha256_file_empty_file(tmp_path: Path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert sha256_file(p) == hashlib.sha256(b"").hexdigest()


def test_stage_status_values_are_distinct_strings():
    values = [StageStatus.OK, StageStatus.PARTIAL, StageStatus.FAILED, StageStatus.UNKNOWN]
    assert len(set(values)) == 4
    assert all(isinstance(v, str) for v in values)


def test_now_iso_is_parseable_utc_timestamp():
    before = datetime.now(timezone.utc)
    stamp = now_iso()
    after = datetime.now(timezone.utc)

    parsed = datetime.fromisoformat(stamp)
    assert parsed.tzinfo is not None
    assert before <= parsed <= after
