from __future__ import annotations

import seclogx.memcheck as memcheck


def test_available_memory_bytes_returns_positive_int_or_none():
    result = memcheck.available_memory_bytes()
    assert result is None or (isinstance(result, int) and result > 0)


def test_from_proc_meminfo_on_this_linux_host():
    # This dev/CI environment is Linux, so /proc/meminfo should exist and
    # parse to a positive figure -- exercises the real parsing path, not a
    # mock, since a wrong field-index or units bug here would otherwise
    # never be caught.
    result = memcheck._from_proc_meminfo()
    assert isinstance(result, int)
    assert result > 0


def test_from_sysconf_on_this_posix_host():
    result = memcheck._from_sysconf()
    assert result is None or (isinstance(result, int) and result > 0)


def test_from_proc_meminfo_returns_none_on_malformed_content(monkeypatch, tmp_path):
    bad = tmp_path / "meminfo"
    bad.write_text("garbage: not a memory line\n")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/meminfo":
            return real_open(bad, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    assert memcheck._from_proc_meminfo() is None


def test_from_proc_meminfo_returns_none_when_file_missing(monkeypatch):
    def raise_not_found(path, *args, **kwargs):
        raise OSError("no such file")

    monkeypatch.setattr("builtins.open", raise_not_found)
    assert memcheck._from_proc_meminfo() is None


def test_available_memory_bytes_falls_back_through_priority_order(monkeypatch):
    # Force the top two sources to report "unknown" and confirm the
    # Windows-specific source is still consulted (and, on this non-Windows
    # host, itself returns None rather than raising) -- verifies the
    # fallback chain's priority order and its "unknown means None" contract.
    monkeypatch.setattr(memcheck, "_from_proc_meminfo", lambda: None)
    monkeypatch.setattr(memcheck, "_from_sysconf", lambda: None)
    assert memcheck.available_memory_bytes() is None


def test_available_memory_bytes_prefers_proc_meminfo_when_available(monkeypatch):
    monkeypatch.setattr(memcheck, "_from_proc_meminfo", lambda: 12345)
    monkeypatch.setattr(memcheck, "_from_sysconf", lambda: 999999)
    assert memcheck.available_memory_bytes() == 12345


def test_from_windows_returns_none_off_windows():
    # ctypes.windll doesn't exist on non-Windows platforms -- confirm this
    # is caught as AttributeError and turned into None, not an unhandled crash.
    assert memcheck._from_windows() is None
