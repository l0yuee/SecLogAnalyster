from __future__ import annotations

import os
from pathlib import Path

import duckdb
import pytest
import yaml

from seclogx import paths as path_module
from seclogx.paths import duckdb_path
from seclogx.detect.hunt import run_hunt
from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.storage import LocalStorageBackend
from seclogx.ingest.compaction import compact_case
from seclogx.ingest.persistence import atomic_json
from seclogx.ingest.snapshots import cleanup_retired
from seclogx.query import CaseDB


@pytest.mark.parametrize("raw,expected", [
    (r"C:\case\lake\part.parquet", r"\\?\C:\case\lake\part.parquet"),
    (r"C:\case\..\case\lake\**\*.parquet", r"\\?\C:\case\lake\**\*.parquet"),
    (r"\\server\share\case\part.parquet", r"\\?\UNC\server\share\case\part.parquet"),
    (r"\\?\C:\case\part.parquet", r"\\?\C:\case\part.parquet"),
    ("s3://bucket/case/part.parquet", "s3://bucket/case/part.parquet"),
    ("https://host/path", "https://host/path"),
])
def test_windows_native_path_normalization(raw, expected, monkeypatch):
    monkeypatch.setattr(path_module, "_WINDOWS", True)
    assert duckdb_path(raw) == expected
    assert duckdb_path(duckdb_path(raw)) == expected


def test_non_windows_native_paths_are_unchanged(monkeypatch):
    monkeypatch.setattr(path_module, "_WINDOWS", False)
    assert duckdb_path("relative/case/*.parquet") == "relative/case/*.parquet"


@pytest.mark.skipif(os.name != "nt", reason="exercises Windows native MAX_PATH boundaries")
def test_deep_parquet_paths_support_query_hunt_compaction_and_retirement(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    backend = LocalStorageBackend()
    location = case / ".ingest" / ("a" * 22) / "lake" / "web_logs" / ("host=" + "H" * 145)
    backend.ensure_dir(str(location))
    original = [location / f"{index}.parquet" for index in range(2)]
    assert all(len(str(path)) > 260 for path in original)
    with duckdb.connect() as con:
        for index, path in enumerate(original):
            target = duckdb_path(path).replace("'", "''")
            con.execute(f"COPY (SELECT {index} AS record_id, 'GET' AS method, 'evidence.log' AS source_path) "
                        f"TO '{target}' (FORMAT PARQUET)")
    atomic_json(case / "case.json", {"catalog_version": 1,
                "catalog": {"web_logs": [path.relative_to(case).as_posix() for path in original]}})
    listed = backend.list_parquet(str(location))
    assert listed == [str(path) for path in original]
    assert all(not path.startswith('\\\\?\\') for path in listed)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "match.yml").write_text(yaml.safe_dump({
        "title": "GET request", "logsource": {"category": "webserver"}, "level": "high",
        "detection": {"selection": {"cs-method": "GET"}, "condition": "selection"},
    }), encoding="utf-8")
    config = ClusterConfig.local()
    with CaseDB(case, config) as previous:
        assert previous.sql("SELECT count(*) n FROM web_logs").iloc[0]["n"] == 2
        matches = run_hunt(case, rules, cluster_config=config)
        assert not matches.failures and matches.total_matches == 2
        assert matches.matches["source_path"].tolist() == ["evidence.log", "evidence.log"]
        compacted = compact_case(case, config)
        assert compacted.input_files == 2 and compacted.output_files == 1
        assert cleanup_retired(case, config) == []
        assert previous.sql("SELECT count(*) n FROM web_logs").iloc[0]["n"] == 2
    removed = cleanup_retired(case, config)
    assert set(removed) == {str(path) for path in original}
    assert all(not Path(duckdb_path(path)).exists() for path in original)
    with CaseDB(case, config) as current:
        assert current.sql("SELECT count(*) n FROM web_logs").iloc[0]["n"] == 2
        assert all(not path.startswith('\\\\?\\') for path in current.parquet_files["web_logs"])
