from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from seclogx.distributed.config import ClusterConfig
from seclogx.ingest import compaction
from seclogx.ingest.transactions import read_metadata
from seclogx.query import CaseDB


def _files(case: Path, count: int, host="HOST", *, extra=False) -> list[Path]:
    partition = case / "lake" / "web_logs" / f"host={host}" / "date=2026-09-20"
    partition.mkdir(parents=True, exist_ok=True)
    paths = []
    for index in range(count):
        columns = {"record_id": [index * 2, index * 2 + 1], "method": ["GET", "POST"],
                   "payload": [f"中文 '{index}' \\ value", None], "source_file": [f"source-{index}.log"] * 2,
                   "ingest_batch_id": [f"batch-{index}"] * 2, "number": [0.25, None],
                   "event_data": [json.dumps({"i": index, "nested": [1, 2]}), "{}"]}
        if extra and index % 2:
            columns["optional_field"] = [None, "present"]
        path = partition / f"part-{index}.parquet"
        pq.write_table(pa.table(columns), path)
        paths.append(path)
    return paths


def _read(case: Path):
    with CaseDB(case) as db:
        return db.sql("SELECT * FROM web_logs ORDER BY host, record_id")


@pytest.mark.parametrize("case_name", ["case", "analyst's case"])
def test_manual_compaction_preserves_every_value_and_keeps_old_readers(tmp_path, case_name):
    case = tmp_path / case_name
    originals = _files(case, 5, extra=True)
    originals += _files(case, 3, "OTHER")
    before = _read(case)
    with CaseDB(case) as old_reader:
        report = compaction.compact_case(case)
        assert report.status == "committed"
        assert (report.input_files, report.output_files, report.rows) == (8, 2, 16)
        pd.testing.assert_frame_equal(before, old_reader.sql("SELECT * FROM web_logs ORDER BY host, record_id"))
    pd.testing.assert_frame_equal(before, _read(case))
    assert all(path.is_file() for path in originals)
    meta = read_metadata(case)
    assert len(meta["catalog"]["web_logs"]) == 2
    assert len(meta["retired_files"]) == 8
    assert meta["maintenance_runs"][0]["transaction_id"] == report.transaction_id
    assert {item["maintenance_id"] for item in meta["retired_files"]} == {report.transaction_id}
    for value in meta["catalog"]["web_logs"]:
        assert pq.ParquetFile(case / value).metadata.row_group(0).column(0).compression == "ZSTD"
    state = read_metadata(case)  # published metadata remains readable after writer close
    assert state["catalog_version"] == 1


def test_automatic_threshold_is_per_partition(tmp_path):
    case = tmp_path / "case"
    _files(case, 127)
    _files(case, 1, "OTHER")
    assert compaction.compact_case(case, automatic=True).status == "skipped"
    additional = case / "lake" / "web_logs" / "host=HOST" / "date=2026-09-20" / "last.parquet"
    pq.write_table(pa.table({"record_id": [1000], "method": ["GET"]}), additional)
    report = compaction.compact_case(case, automatic=True)
    assert report.input_files == 128 and report.output_files == 1
    assert report.rows == 255
    assert len(_read(case)) == 257  # the OTHER partition remains untouched


def test_planner_bounds_compressed_group_size_and_excludes_large_files(tmp_path, monkeypatch):
    case = (tmp_path / "case").resolve()
    files = _files(case, 6)
    sizes = [path.stat().st_size for path in files]
    monkeypatch.setattr(compaction, "_GROUP_BYTES", max(sizes) * 2)
    monkeypatch.setattr(compaction, "_SMALL_FILE_BYTES", max(sizes) + 1)
    groups = compaction._plan_groups(case, {"web_logs": [str(path) for path in files]}, False)
    assert len(groups) == 3
    assert all(len(paths) == 2 for _, _, paths in groups)
    assert all(sum(Path(path).stat().st_size for path in paths) <= compaction._GROUP_BYTES
               for _, _, paths in groups)
    monkeypatch.setattr(compaction, "_SMALL_FILE_BYTES", min(sizes))
    assert not compaction._plan_groups(case, {"web_logs": [str(path) for path in files]}, False)


def test_failed_conversion_leaves_visible_snapshot_unchanged(tmp_path, monkeypatch):
    case = tmp_path / "case"
    originals = _files(case, 3)
    before = _read(case)
    original_write = compaction._write_group

    def fail_after_copy(connection, paths, destination):
        original_write(connection, paths, destination)
        raise OSError("injected output failure")

    monkeypatch.setattr(compaction, "_write_group", fail_after_copy)
    with pytest.raises(OSError, match="injected output failure"):
        compaction.compact_case(case)
    assert not read_metadata(case).get("maintenance_runs")
    pd.testing.assert_frame_equal(before, _read(case))
    assert all(path.exists() for path in originals)


def test_changed_catalog_cannot_be_overwritten_by_compaction(tmp_path, monkeypatch):
    case = tmp_path / "case"
    _files(case, 3)
    original_write = compaction._write_group

    def concurrent_publish(connection, paths, destination):
        count = original_write(connection, paths, destination)
        _files(case, 1, "NEW")
        return count

    monkeypatch.setattr(compaction, "_write_group", concurrent_publish)
    with pytest.raises(RuntimeError, match="catalog changed"):
        compaction.compact_case(case)
    assert set(_read(case)["host"]) == {"HOST", "NEW"}
    assert not read_metadata(case).get("maintenance_runs")


def test_metadata_write_failure_never_retires_visible_files(tmp_path, monkeypatch):
    case = tmp_path / "case"
    originals = _files(case, 3)
    original_atomic = compaction.atomic_json

    def fail_case_metadata(path, data):
        if Path(path).name == "case.json":
            raise OSError("metadata publication failed")
        original_atomic(path, data)

    monkeypatch.setattr(compaction, "atomic_json", fail_case_metadata)
    with pytest.raises(OSError, match="metadata publication failed"):
        compaction.compact_case(case)
    assert len(_read(case)) == 6
    assert all(path.exists() for path in originals)
    assert not read_metadata(case).get("retired_files")


def test_s3_is_explicitly_unsupported_without_attempting_connections(tmp_path):
    config = ClusterConfig(storage_backend="s3", s3_bucket="test")
    assert compaction.compact_case(tmp_path, config, automatic=True).status == "skipped"
    with pytest.raises(NotImplementedError, match="local storage"):
        compaction.compact_case(tmp_path, config)


def test_compaction_fsync_failure_prevents_catalog_publication(tmp_path, monkeypatch):
    import os

    case = tmp_path / "case"
    originals = _files(case, 3)
    before = _read(case)
    original_validate = compaction.validate_outputs

    def fail_flush(*args):
        def failed_fsync(descriptor):
            raise OSError("injected file flush failure")
        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", failed_fsync)
            original_validate(*args)

    monkeypatch.setattr(compaction, "validate_outputs", fail_flush)
    with pytest.raises(OSError, match="injected file flush failure"):
        compaction.compact_case(case)
    assert not read_metadata(case).get("maintenance_runs")
    assert not read_metadata(case).get("retired_files")
    assert all(path.exists() for path in originals)
    pd.testing.assert_frame_equal(before, _read(case))


def test_compaction_flushes_only_owned_outputs_with_windows_compatible_handles(tmp_path, monkeypatch):
    import builtins
    from seclogx.paths import duckdb_path

    case = tmp_path / "case"
    _files(case, 3)
    original_open = builtins.open
    flushed = []

    def observe_open(file, mode="r", *args, **kwargs):
        if isinstance(file, (str, Path)) and Path(file).suffix == ".parquet" and mode == "r+b":
            flushed.append(Path(file))
        return original_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", observe_open)
    report = compaction.compact_case(case)
    assert len(flushed) == report.output_files == 1
    assert all(path.is_relative_to(Path(duckdb_path(case / ".ingest" / report.transaction_id))) for path in flushed)
    assert all(path.name.startswith("compact-") for path in flushed)
