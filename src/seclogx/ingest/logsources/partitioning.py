"""Bounded partition metadata matching the NDJSON VARCHAR input contract.

Unsupported values disable the optimization, so legacy manifests and unusual
parser values still use DuckDB's authoritative partition scan.
"""
from __future__ import annotations

from collections.abc import Mapping

from .schema import TABLES


PartitionRow = tuple[str | None, ...]


class PartitionCollector:
    """Collect raw partition values before path escaping, with bounded storage.

    ``rows`` is None after either bound is exceeded or a value cannot be
    converted without guessing DuckDB's JSON-to-VARCHAR semantics. Callers
    must then retain the existing SELECT DISTINCT fallback. An empty list
    means a complete, empty collection; it is distinct from None.
    """

    def __init__(self, table: str, *, max_partitions: int = 4096, max_bytes: int = 1024 * 1024):
        for name, value in (("max_partitions", max_partitions), ("max_bytes", max_bytes)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        definition = TABLES[table]
        self.columns = tuple(definition["partition_by"])
        types = dict(definition["columns"])
        # Future non-text partition columns must use their canonical casts.
        self._partitions: set[PartitionRow] | None = (
            set() if all(types[column] == "VARCHAR" for column in self.columns) else None
        )
        self._max_partitions = max_partitions
        self._max_bytes = max_bytes
        self._bytes = 0

    def add(self, row: Mapping[str, object]) -> None:
        if self._partitions is None:
            return
        normalized: list[str | None] = []
        for column in self.columns:
            value = row.get(column)
            if value is None or type(value) is str:
                normalized.append(value)
            elif type(value) is bool:
                normalized.append("true" if value else "false")
            elif type(value) is int:
                normalized.append(str(value))
            else:
                # Floats, containers and default=str objects have distinct
                # JSON conversion rules. Falling back preserves those rules.
                self._partitions = None
                return
        partition = tuple(normalized)
        if partition in self._partitions:
            return
        try:
            encoded_bytes = sum(1 if value is None else len(value.encode("utf-8")) + 1
                                for value in partition)
        except UnicodeError:
            self._partitions = None
            return
        if (len(self._partitions) >= self._max_partitions
                or self._bytes + encoded_bytes > self._max_bytes):
            self._partitions = None
            return
        self._partitions.add(partition)
        self._bytes += encoded_bytes

    @property
    def rows(self) -> list[PartitionRow] | None:
        if self._partitions is None:
            return None
        return sorted(self._partitions, key=lambda row: tuple(
            (value is not None, value or "") for value in row
        ))


__all__ = ["PartitionCollector", "PartitionRow"]
