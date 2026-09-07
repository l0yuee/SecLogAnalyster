"""The Hive partition directories DuckDB's COPY creates are pre-created
only on backends that actually race while creating them (Windows local
storage). Enumerating them costs a second full pass over every staged
file, so this test pins both halves: it is skipped where it buys nothing,
and still performed where the race exists.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from seclogx.case import Case
from seclogx.distributed.storage import LocalStorageBackend
from seclogx.ingest.logsources import flatten as flatten_mod
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.query import CaseDB


def _stage(path: Path, hosts: list[str]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for i, host in enumerate(hosts):
            f.write(
                json.dumps(
                    {
                        "host": host,
                        "time_created": "2026-01-01T00:00:00+00:00",
                        "hostname": host,
                        "app_name": "testapp",
                        "message": f"row-{i}",
                    }
                )
                + "\n"
            )
    return str(path)


def _flatten(tmp_path: Path, name: str) -> tuple[Path, int]:
    case = Case.create(name, case_root=tmp_path / "cases")
    ndjson = _stage(tmp_path / f"staging-{name}" / "syslog.ndjson", ["LAB01", "LAB02", "LAB01"])
    rows = flatten_table(case.case_dir, "syslog", [ndjson], "batch", datetime.now(timezone.utc))
    return case.case_dir, rows


def test_partitions_are_written_correctly_without_precreation(tmp_path: Path, monkeypatch):
    """The POSIX path: no pre-creation pass, and DuckDB still lays out
    every Hive partition and every row."""
    monkeypatch.setattr(LocalStorageBackend, "precreates_partition_dirs", property(lambda self: False))

    called: list[tuple] = []
    monkeypatch.setattr(
        flatten_mod, "ensure_hive_partition_dirs", lambda *a, **k: called.append(a)
    )

    case_dir, rows = _flatten(tmp_path, "noprecreate")

    assert not called, "the extra enumeration pass must be skipped where it isn't needed"
    assert rows == 3
    partitions = {p.name for p in (case_dir / "lake" / "syslog").iterdir() if p.is_dir()}
    assert partitions == {"host=LAB01", "host=LAB02"}
    assert len(CaseDB(case_dir).table("syslog")) == 3


def test_partitions_are_precreated_where_the_race_exists(tmp_path: Path, monkeypatch):
    """The Windows path: partition dirs are enumerated and created before
    COPY, so two concurrent writers can't lose a CreateDirectory race."""
    monkeypatch.setattr(LocalStorageBackend, "precreates_partition_dirs", property(lambda self: True))

    called: list[tuple] = []
    real = flatten_mod.ensure_hive_partition_dirs

    def spy(backend, location, columns, rows):
        called.append((tuple(columns), sorted(rows)))
        return real(backend, location, columns, rows)

    monkeypatch.setattr(flatten_mod, "ensure_hive_partition_dirs", spy)

    case_dir, rows = _flatten(tmp_path, "precreate")

    assert called, "the pre-creation pass must still run where the race exists"
    columns, partition_rows = called[0]
    assert columns == ("host",)
    assert partition_rows == [("LAB01",), ("LAB02",)]
    assert rows == 3
    assert len(CaseDB(case_dir).table("syslog")) == 3


def test_local_backend_precreates_only_on_windows(monkeypatch):
    import seclogx.distributed.storage as storage_mod

    monkeypatch.setattr(storage_mod.os, "name", "nt")
    assert LocalStorageBackend().precreates_partition_dirs is True

    monkeypatch.setattr(storage_mod.os, "name", "posix")
    assert LocalStorageBackend().precreates_partition_dirs is False
