from __future__ import annotations

from pathlib import Path

import pytest

from seclogx.discovery import SourceSpec, discover_evtx_files, parse_source_arg


def test_parse_source_arg_plain_path():
    spec = parse_source_arg("/evidence/wks01")
    assert spec.path == Path("/evidence/wks01")
    assert spec.host is None


def test_parse_source_arg_with_host():
    spec = parse_source_arg("/evidence/wks01:WKS01")
    assert spec.path == Path("/evidence/wks01")
    assert spec.host == "WKS01"


def test_parse_source_arg_windows_path_not_mistaken_for_host():
    # A bare Windows-style path shouldn't be misparsed as PATH:HOST.
    spec = parse_source_arg(r"C:\evidence\wks01")
    assert spec.host is None


def test_discover_evtx_files_recursive_and_dedup(tmp_path: Path):
    root = tmp_path / "acquisition"
    (root / "C" / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    evtx1 = root / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    evtx2 = root / "C" / "Windows" / "System32" / "winevt" / "Logs" / "System.EVTX"  # case-insensitive
    not_evtx = root / "readme.txt"
    evtx1.write_bytes(b"fake")
    evtx2.write_bytes(b"fake")
    not_evtx.write_text("not an evtx")

    found = discover_evtx_files([SourceSpec(path=root, host=None)])
    paths = {f.path for f in found}
    assert evtx1.resolve() in paths
    assert evtx2.resolve() in paths
    assert not_evtx.resolve() not in paths
    # host label defaults to the source root's directory name
    assert all(f.host == "acquisition" for f in found)


def test_discover_evtx_files_missing_path_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        discover_evtx_files([SourceSpec(path=tmp_path / "does-not-exist", host=None)])


def test_discover_evtx_files_dedup_across_sources(tmp_path: Path):
    root = tmp_path / "acq"
    root.mkdir()
    f = root / "Security.evtx"
    f.write_bytes(b"fake")

    found = discover_evtx_files([SourceSpec(path=root, host="A"), SourceSpec(path=f, host="B")])
    # same resolved file discovered via two overlapping sources -> only counted once
    assert len(found) == 1
