"""Partition manifests must avoid rescans without changing stored values."""
from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import duckdb
import pytest

from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.storage import LocalStorageBackend
from seclogx.ingest.logsources import flatten as flatten_mod
from seclogx.ingest.logsources.partitioning import PartitionCollector
from seclogx.ingest.resources import IngestOptions


def _write(path: Path, rows: list[dict]) -> str:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, default=str) + "\n" for row in rows),
                    encoding="utf-8")
    return str(path)


def _spy_connections(monkeypatch) -> list[str]:
    statements = []
    original = duckdb.connect

    class Connection:
        def __init__(self, *args, **kwargs):
            self.inner = original(*args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def execute(self, statement, *args, **kwargs):
            statements.append(statement)
            return self.inner.execute(statement, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    monkeypatch.setattr(flatten_mod.duckdb, "connect", Connection)
    return statements


def test_collector_matches_duckdb_json_varchar_and_keeps_null_empty_distinct(tmp_path):
    values = [None, "", True, False, 0, -7, 2**64, "0001", "true", "中文 /%='😀", "line\nfeed"]
    rows = [{"host": value, "log_type": "nginx"} for value in values]
    rows += [{"log_type": "nginx"}, {"host": "H"}]
    collector = PartitionCollector("web_logs")
    for row in rows:
        collector.add(row)
    path = _write(tmp_path / "values.ndjson", rows)
    with duckdb.connect() as con:
        expected = con.execute(
            "SELECT DISTINCT host, log_type FROM read_ndjson(?, columns={'host':'VARCHAR','log_type':'VARCHAR'})",
            [path],
        ).fetchall()
    assert collector.rows is not None
    assert set(collector.rows) == set(expected)
    assert (None, "nginx") in collector.rows
    assert ("", "nginx") in collector.rows
    assert pickle.loads(pickle.dumps(collector.rows)) == collector.rows
    assert json.loads(json.dumps(collector.rows)) == [list(row) for row in collector.rows]


@pytest.mark.parametrize("value", [1.25, {"nested": 1}, ["host"], datetime(2026, 1, 1)])
def test_unproven_conversion_disables_collection(value):
    collector = PartitionCollector("syslog")
    collector.add({"host": "safe"})
    collector.add({"host": value})
    collector.add({"host": "later"})
    assert collector.rows is None


def test_collection_bounds_release_prior_metadata_and_remain_disabled():
    collector = PartitionCollector("syslog", max_partitions=2)
    for host in ("a", "a", "b"):
        collector.add({"host": host})
    assert collector.rows == [("a",), ("b",)]
    collector.add({"host": "c"})
    collector.add({"host": "a"})
    assert collector.rows is None
    collector = PartitionCollector("syslog", max_bytes=4)
    collector.add({"host": "中"})  # Three UTF-8 bytes and one separator.
    assert collector.rows == [("中",)]
    collector.add({"host": "x"})
    assert collector.rows is None


@pytest.mark.parametrize("option", ["max_partitions", "max_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_bounds_rejected(option, value):
    with pytest.raises(ValueError, match=option):
        PartitionCollector("syslog", **{option: value})


@pytest.mark.parametrize("known_partitions", [True, False])
def test_windows_precreation_preserved_and_known_rows_skip_distinct(tmp_path, monkeypatch, known_partitions):
    monkeypatch.setattr(LocalStorageBackend, "precreates_partition_dirs", property(lambda self: True))
    hosts = ["", None, True, False, "中文 /%='😀"]
    rows = [{"host": host, "message": str(i)} for i, host in enumerate(hosts)]
    collector = PartitionCollector("syslog")
    for row in rows:
        collector.add(row)
    path = _write(tmp_path / "syslog.ndjson", rows)
    case_dir = tmp_path / "case"
    statements = _spy_connections(monkeypatch)
    precreated = []
    real_precreate = flatten_mod.ensure_hive_partition_dirs

    def precreate(backend, location, columns, partitions):
        precreated.extend(tuple(row) for row in partitions)
        real_precreate(backend, location, columns, precreated)
        # This runs before COPY, retaining the Windows mkdir protection.
        for row in precreated:
            value = "__HIVE_DEFAULT_PARTITION__" if row[0] is None else quote(row[0], safe="")
            assert (Path(location) / f"host={value}").is_dir()

    monkeypatch.setattr(flatten_mod, "ensure_hive_partition_dirs", precreate)
    written = flatten_mod.flatten_table(
        case_dir, "syslog", [path], "batch", datetime.now(timezone.utc),
        cluster_config=ClusterConfig.local(), options=IngestOptions(memory_limit="128MB", threads=1),
        partition_rows=collector.rows if known_partitions else None,
    )
    assert written == len(rows)
    assert set(precreated) == set(collector.rows)
    scans = [statement for statement in statements if statement.startswith("SELECT DISTINCT")]
    assert len(scans) == (0 if known_partitions else 1)
    with duckdb.connect() as con:
        persisted = con.execute(
            "SELECT host, message FROM read_parquet(?, hive_partitioning=true) ORDER BY message",
            [str(case_dir / "lake" / "syslog" / "**" / "*.parquet")],
        ).fetchall()
    assert persisted == [("", "0"), (None, "1"), ("true", "2"), ("false", "3"), (hosts[-1], "4")]


def test_non_windows_backend_needs_no_precreation_or_distinct(tmp_path, monkeypatch):
    monkeypatch.setattr(LocalStorageBackend, "precreates_partition_dirs", property(lambda self: False))
    path = _write(tmp_path / "syslog.ndjson", [{"host": "H", "message": "ok"}])
    statements = _spy_connections(monkeypatch)

    def unexpected(*args):
        raise AssertionError("This backend must not precreate partition directories")

    monkeypatch.setattr(flatten_mod, "ensure_hive_partition_dirs", unexpected)
    assert flatten_mod.flatten_table(
        tmp_path / "case", "syslog", [path], "batch", datetime.now(timezone.utc),
        cluster_config=ClusterConfig.local(), options=IngestOptions(memory_limit="128MB", threads=1),
        partition_rows=[("H",)],
    ) == 1
    assert not any(statement.startswith("SELECT DISTINCT") for statement in statements)
