"""Best-effort available-system-memory check, used to decide whether a
query result is safe to hand the analyst as one in-memory DataFrame or
needs an alternative (chunked/streamed) delivery instead -- see search.py.

No new dependency (no psutil): tries /proc/meminfo (Linux, accounts for
reclaimable cache so it's the most accurate "available" figure), then
os.sysconf (POSIX, coarser -- free pages, not reclaimable-aware), then
Windows' GlobalMemoryStatusEx via ctypes. Returns None if none of these
work, which callers must treat as "unknown" (be conservative), not zero.
"""

from __future__ import annotations

import ctypes
import os


def available_memory_bytes() -> int | None:
    from_proc = _from_proc_meminfo()
    if from_proc is not None:
        return from_proc

    from_sysconf = _from_sysconf()
    if from_sysconf is not None:
        return from_sysconf

    return _from_windows()


def _from_proc_meminfo() -> int | None:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _from_sysconf() -> int | None:
    try:
        if "SC_AVPHYS_PAGES" in os.sysconf_names and "SC_PAGE_SIZE" in os.sysconf_names:
            return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        pass
    return None


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _from_windows() -> int | None:
    try:
        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            return int(stat.ullAvailPhys)
    except (AttributeError, OSError):
        pass
    return None
