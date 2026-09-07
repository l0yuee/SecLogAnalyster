"""Coverage for the os.scandir-based source walk in `ingest/scan.py`:
the symlink semantics and cross-source dedup it has to preserve (it
replaced a `Path.rglob` + `resolve()` + `stat()` walk), and the walk-phase
progress it now reports.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seclogx.ingest.common import SourceSpec
from seclogx.ingest.scan import scan_sources

_SYSLOG_LINE = "<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n"


def test_walk_follows_file_symlinks_but_not_directory_symlinks(tmp_path: Path):
    """Matches what `rglob("*")` + `Path.is_file()` did before: a symlink
    to a log file is that log file, while a symlinked directory is not
    descended into (which is also what keeps a symlink cycle from hanging
    the walk)."""
    root = tmp_path / "acq"
    real = tmp_path / "outside"
    real.mkdir()
    root.mkdir()

    target = real / "real.log"
    target.write_text(_SYSLOG_LINE)
    (root / "link.log").symlink_to(target)

    # A directory symlink pointing back at an ancestor: descending it would
    # recurse forever.
    (root / "loop").symlink_to(tmp_path, target_is_directory=True)

    result = scan_sources([SourceSpec(path=root, host="H")])

    names = {f.path.name for f in result.aux_files}
    assert names == {"link.log"}, "the file symlink should be followed and classified"
    assert result.aux_files[0].kind == "syslog"


def test_walk_dedups_the_same_file_reached_two_ways(tmp_path: Path):
    """Dedup is by (st_dev, st_ino) now rather than resolved path, so a
    file reached through two overlapping sources -- via a symlink in one
    and directly in the other -- is still staged once."""
    root = tmp_path / "acq"
    root.mkdir()
    real = root / "auth.log"
    real.write_text(_SYSLOG_LINE)

    other = tmp_path / "second"
    other.mkdir()
    (other / "auth-alias.log").symlink_to(real)

    result = scan_sources([SourceSpec(path=root, host="A"), SourceSpec(path=other, host="B")])
    assert len(result.aux_files) == 1


def test_walk_dedups_hard_links(tmp_path: Path):
    """A hard link is the same file by inode -- resolve()-based dedup
    missed this, inode-based dedup catches it."""
    root = tmp_path / "acq"
    root.mkdir()
    original = root / "auth.log"
    original.write_text(_SYSLOG_LINE)
    (root / "auth-hardlink.log").hardlink_to(original)

    result = scan_sources([SourceSpec(path=root, host="A")])
    assert len(result.aux_files) == 1


def test_walk_skips_unreadable_directories_without_failing(tmp_path: Path):
    root = tmp_path / "acq"
    (root / "readable").mkdir(parents=True)
    (root / "readable" / "auth.log").write_text(_SYSLOG_LINE)
    locked = root / "locked"
    locked.mkdir()
    (locked / "hidden.log").write_text(_SYSLOG_LINE)
    locked.chmod(0o000)
    try:
        result = scan_sources([SourceSpec(path=root, host="A")])
    finally:
        locked.chmod(0o755)

    if not result.aux_files:  # running as root, which can read it anyway
        pytest.skip("cannot make a directory unreadable as this user")
    assert {f.path.name for f in result.aux_files} == {"auth.log"}


def test_walk_reports_progress_while_walking(tmp_path: Path):
    """The walk is the first thing an ingest does and used to be entirely
    silent -- it now reports a running file count, and always reports the
    final total even when the tree is smaller than the batch interval."""
    root = tmp_path / "acq"
    root.mkdir()
    for i in range(12):
        (root / f"auth{i}.log").write_text(_SYSLOG_LINE)

    walked: list[int] = []
    scan_sources([SourceSpec(path=root, host="H")], on_walked=walked.append)

    assert walked, "the walk must report progress"
    assert walked[-1] == 12, "the final count must be the true total"
    assert walked == sorted(walked), "the running count must be monotonic"


def test_dedup_falls_back_to_paths_when_the_platform_reports_no_inode(tmp_path: Path, monkeypatch):
    """Windows' `os.DirEntry.stat()` documents st_ino/st_dev as always
    zero. Keying dedup on that verbatim would collapse every file onto one
    key and silently drop the whole acquisition after the first file, so a
    zero inode must fall back to path identity."""
    import seclogx.ingest.scan as scan_mod

    root = tmp_path / "acq"
    root.mkdir()
    for i in range(4):
        (root / f"auth{i}.log").write_text(_SYSLOG_LINE)

    real_identity = scan_mod._identity

    def zeroed_inode_identity(path, st):
        class _NoInode:
            st_ino = 0
            st_dev = 0
            st_size = st.st_size
            st_mode = st.st_mode

        return real_identity(path, _NoInode())

    monkeypatch.setattr(scan_mod, "_identity", zeroed_inode_identity)

    result = scan_sources([SourceSpec(path=root, host="H")])
    assert len(result.aux_files) == 4, "every distinct file must survive dedup without inode support"


def test_walk_accepts_a_single_file_as_a_source(tmp_path: Path):
    single = tmp_path / "auth.log"
    single.write_text(_SYSLOG_LINE)

    result = scan_sources([SourceSpec(path=single, host="H")])
    assert [f.path.name for f in result.aux_files] == ["auth.log"]
    assert result.aux_files[0].kind == "syslog"
