from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from seclogx import Case
from seclogx.ingest import compaction, transactions
from seclogx.ingest.common import SourceSpec
from seclogx.ingest.logsources.orchestrator import run_aux_ingest
from seclogx.ingest.snapshots import cleanup_retired
from seclogx.paths import duckdb_path


@pytest.fixture
def legacy_case(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with Case.create("legacy", case_root=tmp_path / "cases") as case:
        for index in range(3):
            path = source / f"{index}.log"
            path.write_text(f"<34>1 2026-09-20T00:00:00Z host app 1 - - source {index}\n" * 10,
                            encoding="utf-8")
            # Separate old-style imports create actual mergeable files,
            # without installing a catalog or source ledger beforehand.
            run_aux_ingest(case.case_dir, [SourceSpec(path, "OLD")], workers=1)
        assert "catalog" not in case.info()
        assert len(list((case.case_dir / "lake").rglob("*.parquet"))) == 3
        yield case, source


def test_compacted_legacy_sources_are_adopted_before_reimport(legacy_case):
    case, source = legacy_case
    compacted = case.compact()
    assert compacted.input_files == 3 and compacted.output_files == 1
    assert case.info()["legacy_provenance_pending"] is True
    assert case.info()["catalog_storage"] == ["local"]
    assert "legacy_ledger" not in case.info()

    report = case.ingest([f"{source}:OLD"], workers=1)
    assert len(report.already_imported) == 3
    assert {entry["status"] for entry in report.already_imported} == {"legacy_unknown"}
    assert not case.info().get("legacy_provenance_pending")
    assert len(case.info()["legacy_ledger"]) == 3
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 30
    assert len(case.ingest([f"{source}:OLD"], workers=1).already_imported) == 3
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 30

    case.ingest([f"{source}:OTHER"], workers=1)
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 60
    assert set(case.query("SELECT DISTINCT host FROM syslog")["host"]) == {"OLD", "OTHER"}


def test_failed_adoption_keeps_pending_flag_and_retry_does_not_duplicate(legacy_case, monkeypatch):
    case, source = legacy_case
    case.compact()
    before = case.info()
    original_atomic = transactions.atomic_json

    def fail_ledger_publication(path, value):
        if Path(path) == case.case_dir / "case.json" and "legacy_ledger" in value:
            raise OSError("injected legacy ledger publication failure")
        original_atomic(path, value)

    monkeypatch.setattr(transactions, "atomic_json", fail_ledger_publication)
    with pytest.raises(OSError, match="ledger publication failure"):
        case.ingest([f"{source}:OLD"], workers=1)
    assert case.info() == before
    assert case.info()["legacy_provenance_pending"] is True
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 30
    monkeypatch.setattr(transactions, "atomic_json", original_atomic)
    assert len(case.ingest([f"{source}:OLD"], workers=1).already_imported) == 3
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 30
    assert not case.info().get("legacy_provenance_pending")


def test_missing_legacy_provenance_still_allows_analysis_but_blocks_ingest(tmp_path):
    source = tmp_path / "new.log"
    source.write_text("<34>1 2026-09-20T00:00:00Z host app 1 - - new record\n", encoding="utf-8")
    with Case.create("missing", case_root=tmp_path / "cases") as case:
        partition = case.case_dir / "lake" / "syslog" / "host=OLD"
        partition.mkdir(parents=True)
        for index in range(2):
            pq.write_table(pa.table({"message": [f"old {index}"]}), partition / f"{index}.parquet")
        assert case.compact().status == "committed"
        before = case.info()
        assert before["legacy_provenance_pending"] is True
        with pytest.raises(ValueError, match="legacy lake lacks provenance columns"):
            case.ingest([str(source)], workers=1)
        assert case.info() == before
        assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 2


def test_pending_adoption_leases_managed_files_through_snapshot_recheck(legacy_case, monkeypatch):
    case, source = legacy_case
    originals = list((case.case_dir / "lake").rglob("*.parquet"))
    with monkeypatch.context() as patch:
        patch.setattr(compaction, "_GROUP_BYTES", 2 * max(path.stat().st_size for path in originals))
        first = case.compact()
    assert first.input_files == 2 and first.output_files == 1
    files = transactions.catalog_files(case.case_dir, compaction.get_storage_backend(case.cluster_config))
    managed = [path for paths in files.values() for path in paths if ".ingest" in Path(path).parts]
    assert len(managed) == 1
    original_lock = transactions.get_case_lock
    injected = False

    @contextmanager
    def compact_before_adoption_publication(case_dir, config):
        nonlocal injected
        leased = any(set(managed).issubset(json.loads(path.read_text(encoding="utf-8"))["files"])
                     for path in (Path(case_dir) / ".readers").glob("*.json"))
        if not injected and leased:
            injected = True
            # Publish a newer snapshot after adoption scanned the old one.
            # Its old managed file is now retired, but the adoption lease
            # must prevent reclamation until the stale publication fails.
            assert compaction.compact_case(case_dir, config).status == "committed"
            assert transactions.read_metadata(case_dir)["legacy_provenance_pending"] is True
            assert cleanup_retired(case_dir, config) == []
            assert all(Path(duckdb_path(path)).exists() for path in managed)
        with original_lock(case_dir, config) as lock:
            yield lock

    monkeypatch.setattr(transactions, "get_case_lock", compact_before_adoption_publication)
    with pytest.raises(RuntimeError, match="legacy case changed during adoption"):
        case.ingest([f"{source}:OLD"], workers=1)
    assert set(cleanup_retired(case.case_dir, case.cluster_config)) == set(managed)
    assert case.info()["legacy_provenance_pending"] is True
    monkeypatch.setattr(transactions, "get_case_lock", original_lock)
    assert len(case.ingest([f"{source}:OLD"], workers=1).already_imported) == 3
    assert case.query("SELECT count(*) n FROM syslog").iloc[0, 0] == 30
