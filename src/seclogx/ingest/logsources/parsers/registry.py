"""Parse Windows Registry hive files (SYSTEM, SOFTWARE, SAM, SECURITY,
DEFAULT, NTUSER.DAT, UsrClass.dat -- and, since regipy already supports
it for free, AmCache.hve/BCD too) into one row per value, plus one row
per key that has zero values so key existence/last-write-time isn't
silently lost.

Delegates the actual binary hive format (regf/HBIN/NK/VK cells) to
`regipy` rather than hand-rolling it -- the same "trust a battle-tested
library for a complex binary forensic format" choice this project
already makes for `.evtx` (see `ingest/evtx/`).

Deliberately does NOT use `RegistryHive.recurse_subkeys()` -- it doesn't
expose `trim_values`, and its default (`trim_values=True`) silently
truncates every value to 256 bytes and pre-hex-encodes REG_BINARY,
which would both wreck entropy calculation and quietly drop the tail of
any real-sized payload. `_walk()` below re-implements the same
key/value recursion directly against `NKRecord.iter_subkeys()`/
`.iter_values(trim_values=False)` for full-fidelity data, with
per-key/per-subtree exception isolation so a corrupted branch of a hive
doesn't lose everything gathered elsewhere in it (same "a corrupted
chunk aborts the rest of a file's parse" limitation already accepted for
EVTX, not a bug).

See docs/known_limitations.md for what this does and doesn't attempt:
no live-registry merge/aliasing (each hive is normalized rooted at its
own logical path, not merged into one simulated live registry),
best-effort transaction-log recovery, and hive-type identification that
trusts the hive's own embedded original path (not the on-disk filename).
"""

from __future__ import annotations

import math
import os
import tempfile
from collections import Counter
from pathlib import Path

from regipy.exceptions import RegipyException
from regipy.hive_types import (
    AMCACHE_HIVE_TYPE,
    BCD_HIVE_TYPE,
    NTUSER_HIVE_TYPE,
    SAM_HIVE_TYPE,
    SECURITY_HIVE_TYPE,
    SOFTWARE_HIVE_TYPE,
    SYSTEM_HIVE_TYPE,
    USRCLASS_HIVE_TYPE,
)
from regipy.recovery import apply_transaction_logs
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

_BINARY_VALUE_TYPES = {
    "REG_BINARY",
    "REG_NONE",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
}
# Full raw bytes are always used for entropy/value_size; only the *stored*
# hex representation is capped, to bound Parquet growth from a
# pathologically large blob without losing the analysis-relevant numbers.
_HEX_STORAGE_CAP_BYTES = 8192

_HIVE_ROOTS = {
    SYSTEM_HIVE_TYPE: "HKEY_LOCAL_MACHINE\\SYSTEM",
    SOFTWARE_HIVE_TYPE: "HKEY_LOCAL_MACHINE\\SOFTWARE",
    SAM_HIVE_TYPE: "HKEY_LOCAL_MACHINE\\SAM",
    SECURITY_HIVE_TYPE: "HKEY_LOCAL_MACHINE\\SECURITY",
    AMCACHE_HIVE_TYPE: "HKEY_LOCAL_MACHINE\\AMCACHE",
    BCD_HIVE_TYPE: "BCD00000000",
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in Counter(data).values())
    return entropy + 0.0  # normalize away a possible floating-point -0.0


def _find_sibling(path: Path, suffix: str) -> Path | None:
    target = (path.name + suffix).lower()
    try:
        for candidate in path.parent.iterdir():
            if candidate.name.lower() == target:
                return candidate
    except OSError:
        pass
    return None


def _maybe_recover(path: Path) -> tuple[Path, bool, Path | None]:
    """Best-effort transaction-log (.LOG1/.LOG2) replay. Returns (path to
    actually parse, whether recovery was applied, a temp file to clean up
    afterward). Never raises -- any failure just falls back to parsing
    the raw hive as found."""
    log1 = _find_sibling(path, ".log1")
    if not log1:
        return path, False, None
    log2 = _find_sibling(path, ".log2")
    fd, restored_path = tempfile.mkstemp(suffix=".seclogx_restored_hive")
    os.close(fd)
    try:
        apply_transaction_logs(
            str(path),
            str(log1),
            secondary_log_path=str(log2) if log2 else None,
            restored_hive_path=restored_path,
        )
        return Path(restored_path), True, Path(restored_path)
    except Exception:
        Path(restored_path).unlink(missing_ok=True)
        return path, False, None


def _derive_user_root(source_path: Path, is_usrclass: bool) -> str:
    """Mirrors scheduled_tasks._derive_task_path's approach: look for a
    recognizable `Users` directory segment in the source path and take the
    next one as the owning username; fall back to the parent directory
    name if the acquisition layout doesn't have one."""
    suffix = "\\_Classes" if is_usrclass else ""
    parts = source_path.parts
    # Acquisition paths can themselves live below an analyst's ``Users``
    # directory (for example a temporary test/evidence workspace).  The
    # innermost marker belongs to the captured hive, so search right-to-left.
    for i in range(len(parts) - 2, -1, -1):
        part = parts[i]
        if part.lower() == "users" and i + 1 < len(parts):
            return f"HKEY_USERS\\{parts[i + 1]}{suffix}"
    label = source_path.parent.name or "UNKNOWN_USER"
    return f"HKEY_USERS\\{label}{suffix}"


def _identify_hive_type(hive: RegistryHive) -> str:
    if hive.hive_type:
        return hive.hive_type
    # regipy doesn't identify the DEFAULT hive (not in its
    # SUPPORTED_HIVE_TYPES) -- one extra cheap check of the hive's own
    # embedded original path before giving up.
    embedded = (hive.name or "").lower()
    if embedded.endswith("\\config\\default") or embedded == "default":
        return "default"
    return "unknown"


def _hive_root(hive_type: str, source_path: Path, embedded_name: str) -> str:
    if hive_type in _HIVE_ROOTS:
        return _HIVE_ROOTS[hive_type]
    if hive_type == "default":
        return "HKEY_USERS\\.DEFAULT"
    if hive_type in (NTUSER_HIVE_TYPE, USRCLASS_HIVE_TYPE):
        return _derive_user_root(source_path, is_usrclass=(hive_type == USRCLASS_HIVE_TYPE))
    return f"UNKNOWN\\{embedded_name}"


def _value_size(value_type: str, v) -> int | None:
    if isinstance(v, bytes):
        return len(v)
    if isinstance(v, str):
        return len(v.encode("utf-16-le"))
    if isinstance(v, list):
        return sum(len(s.encode("utf-16-le")) + 2 for s in v)
    if isinstance(v, int):
        return 8 if value_type == "REG_QWORD" else 4
    return None


def _base_row(host: str, hive_type: str, hive_root: str, key_path: str, key_last_write, tx_log: bool) -> dict:
    key_path = key_path or "\\"
    full_path = hive_root if key_path == "\\" else f"{hive_root}{key_path}"
    return {
        "host": host,
        "hive_type": hive_type,
        "hive_root": hive_root,
        "key_path": key_path,
        "full_path": full_path,
        "key_last_write_time": key_last_write.isoformat() if key_last_write else None,
        "value_name": None,
        "value_type": None,
        "value_text": None,
        "value_int": None,
        "value_data_hex": None,
        "value_size": None,
        "entropy": None,
        "transaction_log_applied": tx_log,
    }


def _value_to_row(host: str, hive_type: str, hive_root: str, key_path: str, key_last_write, value, tx_log: bool) -> dict:
    row = _base_row(host, hive_type, hive_root, key_path, key_last_write, tx_log)
    row["value_name"] = value.name
    row["value_type"] = value.value_type
    v = value.value
    row["value_size"] = _value_size(value.value_type, v)

    if value.value_type in ("REG_SZ", "REG_EXPAND_SZ") and isinstance(v, str):
        row["value_text"] = v
    elif value.value_type == "REG_MULTI_SZ" and isinstance(v, list):
        row["value_text"] = "\n".join(v)
    elif value.value_type in ("REG_DWORD", "REG_QWORD") and isinstance(v, int):
        row["value_int"] = v
    elif isinstance(v, bytes):
        row["value_data_hex"] = v[:_HEX_STORAGE_CAP_BYTES].hex()
        if value.value_type in _BINARY_VALUE_TYPES:
            row["entropy"] = _shannon_entropy(v)
    elif v is not None:
        row["value_text"] = str(v)

    return row


def _walk(nk, key_path: str, rows: list[dict], host: str, hive_type: str, hive_root: str, tx_log: bool) -> int:
    error_count = 0
    key_last_write = convert_wintime(nk.header.last_modified)

    values = []
    if nk.values_count:
        try:
            values = list(nk.iter_values(trim_values=False))
        except RegipyException:
            error_count += 1

    if not values:
        rows.append(_base_row(host, hive_type, hive_root, key_path, key_last_write, tx_log))
    else:
        for value in values:
            rows.append(_value_to_row(host, hive_type, hive_root, key_path, key_last_write, value, tx_log))

    if nk.subkey_count:
        try:
            children = list(nk.iter_subkeys())
        except RegipyException:
            children = []
            error_count += 1
        for child in children:
            child_path = f"{key_path}\\{child.name}" if key_path else f"\\{child.name}"
            try:
                error_count += _walk(child, child_path, rows, host, hive_type, hive_root, tx_log)
            except RegipyException:
                error_count += 1

    return error_count


def parse_registry_hive_file(path: Path, host: str) -> tuple[list[dict], int, int]:
    parse_path, transaction_log_applied, cleanup_path = _maybe_recover(path)
    try:
        hive = RegistryHive(str(parse_path))
        hive_type = _identify_hive_type(hive)
        hive_root = _hive_root(hive_type, path, hive.name or "")

        rows: list[dict] = []
        error_count = _walk(hive.root, "", rows, host, hive_type, hive_root, transaction_log_applied)
        return rows, len(rows), error_count
    finally:
        if cleanup_path:
            cleanup_path.unlink(missing_ok=True)
