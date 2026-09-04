from __future__ import annotations

from pathlib import Path

import pytest

from seclogx.ingest.common import SourceSpec
from seclogx.ingest.scan import scan_sources


def test_scan_sources_buckets_evtx_and_aux_in_one_pass(tmp_path: Path):
    root = tmp_path / "acquisition"
    (root / "C" / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    evtx = root / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    evtx.write_bytes(b"fake")

    syslog = root / "auth.log"
    syslog.write_text("<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n")

    junk = root / "blob.bin"
    junk.write_bytes(b"\x00" * 4096)

    result = scan_sources([SourceSpec(path=root, host="HOST01")])

    assert {f.path for f in result.evtx_files} == {evtx.resolve()}
    assert {f.path for f in result.aux_files} == {syslog.resolve(), junk.resolve()}
    kinds = {f.path: f.kind for f in result.aux_files}
    assert kinds[syslog.resolve()] == "syslog"
    assert kinds[junk.resolve()] is None  # unrecognized, reported not dropped
    assert all(f.host == "HOST01" for f in result.evtx_files)
    assert all(f.host == "HOST01" for f in result.aux_files)


def test_scan_sources_dedups_across_overlapping_sources(tmp_path: Path):
    root = tmp_path / "acq"
    root.mkdir()
    evtx = root / "Security.evtx"
    evtx.write_bytes(b"fake")
    aux = root / "auth.log"
    aux.write_text("<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n")

    result = scan_sources([SourceSpec(path=root, host="A"), SourceSpec(path=root, host="B")])
    assert len(result.evtx_files) == 1
    assert len(result.aux_files) == 1


def test_scan_sources_missing_path_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        scan_sources([SourceSpec(path=tmp_path / "does-not-exist", host=None)])


def test_scan_sources_reports_progress_for_every_aux_file(tmp_path: Path):
    root = tmp_path / "acq"
    root.mkdir()
    for i in range(10):
        (root / f"auth{i}.log").write_text(
            f"<34>1 2026-01-01T00:00:0{i % 10}Z host01 sshd 123 - - Failed password {i}\n"
        )

    seen: list[int] = []
    result = scan_sources([SourceSpec(path=root, host="HOST01")], on_scanned=seen.append)

    assert len(result.aux_files) == 10
    # on_scanned is called once per classified file with a running total;
    # order across threads isn't guaranteed, but every count 1..10 appears
    # exactly once.
    assert sorted(seen) == list(range(1, 11))


def test_discover_and_classify_and_discover_evtx_files_still_work_standalone(tmp_path: Path):
    """The pre-existing single-pipeline entry points must keep behaving
    identically now that they're thin wrappers over scan_sources()."""
    from seclogx.ingest.evtx.discovery import discover_evtx_files
    from seclogx.ingest.logsources.discovery import discover_and_classify

    root = tmp_path / "acq"
    root.mkdir()
    evtx = root / "Security.evtx"
    evtx.write_bytes(b"fake")
    aux = root / "auth.log"
    aux.write_text("<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n")

    evtx_found = discover_evtx_files([SourceSpec(path=root, host="HOST01")])
    assert {f.path for f in evtx_found} == {evtx.resolve()}

    aux_found = discover_and_classify([SourceSpec(path=root, host="HOST01")])
    assert {f.path for f in aux_found} == {aux.resolve()}
