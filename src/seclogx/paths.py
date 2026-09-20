"""Internal native-engine paths, separate from stored evidence provenance."""
from __future__ import annotations

import ntpath
import os
import re

_WINDOWS = os.name == "nt"
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def duckdb_path(location: str | os.PathLike[str]) -> str:
    """Give DuckDB an absolute Windows extended path for local filesystem I/O.

    Apply at the engine boundary, including short output roots whose Hive
    partition children may exceed MAX_PATH. Keep catalog and source_path
    values unchanged. Remote URIs and non-Windows paths pass through.
    """
    value = os.fspath(location)
    if not _WINDOWS or _URI.match(value):
        return value
    value = ntpath.abspath(value).replace("/", "\\")
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value
