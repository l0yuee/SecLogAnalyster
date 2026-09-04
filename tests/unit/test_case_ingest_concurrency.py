"""Case.ingest() now scans the source tree once (ingest.scan.scan_sources)
and runs the EVTX and aux pipelines concurrently instead of back-to-back,
splitting the local worker budget between them when both have work and no
explicit --workers was given. These tests monkeypatch the two orchestrator
entry points (seclogx.case.run_ingest / run_aux_ingest) rather than doing a
real EVTX parse, so they can assert on exactly what Case.ingest() passed
each pipeline without needing a real .evtx fixture.
"""

from __future__ import annotations

import threading
from pathlib import Path

import seclogx.case as case_module
from seclogx.case import Case
from seclogx.distributed.queue import DEFAULT_LOCAL_INGEST_WORKERS
from seclogx.ingest.evtx.manifest import IngestReport
from seclogx.ingest.jobs import ProgressReporter
from seclogx.ingest.logsources.manifest import AuxIngestReport


def _fake_ingest_report(files_discovered: int) -> IngestReport:
    return IngestReport(
        batch_id="evtx-batch",
        case_name="c",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        files_discovered=files_discovered,
        files_ok=files_discovered,
        files_partial=0,
        files_failed=0,
        records_staged=0,
        records_flattened=0,
    )


def _fake_aux_report(files_discovered: int) -> AuxIngestReport:
    return AuxIngestReport(
        batch_id="aux-batch",
        files_discovered=files_discovered,
        files_ok=files_discovered,
        files_partial=0,
        files_failed=0,
        files_unknown=0,
        unknown_samples=[],
        rows_written={},
        problem_files=[],
    )


def _build_source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "Security.evtx").write_bytes(b"fake")
    (root / "auth.log").write_text("<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n")
    return root


def test_ingest_calls_both_pipelines_concurrently_with_split_workers(tmp_path: Path, monkeypatch):
    root = _build_source_tree(tmp_path)
    calls: dict[str, dict] = {}
    concurrently_running = threading.Event()
    barrier = threading.Barrier(2, timeout=5)

    def fake_run_ingest(*, discovered, workers, progress, **kwargs):
        barrier.wait()  # only passes if both fakes are executing at once
        concurrently_running.set()
        calls["evtx"] = {"discovered": discovered, "workers": workers, "progress": progress}
        return _fake_ingest_report(len(discovered))

    def fake_run_aux_ingest(case_dir, sources, *, classified, workers, progress, **kwargs):
        barrier.wait()
        calls["aux"] = {"classified": classified, "workers": workers, "progress": progress}
        return _fake_aux_report(len(classified))

    monkeypatch.setattr(case_module, "run_ingest", fake_run_ingest)
    monkeypatch.setattr(case_module, "run_aux_ingest", fake_run_aux_ingest)

    c = Case.create("c", case_root=tmp_path / "cases")
    report = c.ingest([str(root)])

    assert concurrently_running.is_set()
    assert len(calls["evtx"]["discovered"]) == 1
    assert len(calls["aux"]["classified"]) == 1
    expected_split = max(1, DEFAULT_LOCAL_INGEST_WORKERS // 2)
    assert calls["evtx"]["workers"] == expected_split
    assert calls["aux"]["workers"] == expected_split
    assert calls["evtx"]["progress"] is None  # no on_progress given -> no reporter constructed
    assert calls["aux"]["progress"] is None
    assert report.files_discovered == 1
    assert report.aux.files_discovered == 1


def test_ingest_does_not_split_workers_when_only_aux_has_files(tmp_path: Path, monkeypatch):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "auth.log").write_text("<34>1 2026-01-01T00:00:00Z host01 sshd 123 - - Failed password\n")

    calls: dict[str, dict] = {}

    def fake_run_ingest(*, discovered, workers, progress, **kwargs):
        calls["evtx"] = {"discovered": discovered, "workers": workers}
        raise case_module.NoSourcesFoundError("no evtx")

    def fake_run_aux_ingest(case_dir, sources, *, classified, workers, progress, **kwargs):
        calls["aux"] = {"classified": classified, "workers": workers}
        return _fake_aux_report(len(classified))

    monkeypatch.setattr(case_module, "run_ingest", fake_run_ingest)
    monkeypatch.setattr(case_module, "run_aux_ingest", fake_run_aux_ingest)

    c = Case.create("c", case_root=tmp_path / "cases")
    report = c.ingest([str(root)])

    # Only one pipeline had work -- it should get the full default budget,
    # not half of it.
    assert calls["aux"]["workers"] is None
    assert report.files_discovered == 0
    assert report.aux.files_discovered == 1


def test_ingest_respects_explicit_workers_even_with_both_pipelines_present(tmp_path: Path, monkeypatch):
    root = _build_source_tree(tmp_path)
    calls: dict[str, dict] = {}

    def fake_run_ingest(*, discovered, workers, progress, **kwargs):
        calls["evtx_workers"] = workers
        return _fake_ingest_report(len(discovered))

    def fake_run_aux_ingest(case_dir, sources, *, classified, workers, progress, **kwargs):
        calls["aux_workers"] = workers
        return _fake_aux_report(len(classified))

    monkeypatch.setattr(case_module, "run_ingest", fake_run_ingest)
    monkeypatch.setattr(case_module, "run_aux_ingest", fake_run_aux_ingest)

    c = Case.create("c", case_root=tmp_path / "cases")
    c.ingest([str(root)], workers=3)

    assert calls["evtx_workers"] == 3
    assert calls["aux_workers"] == 3


def test_ingest_on_progress_builds_reporter_and_reports_terminal_phase(tmp_path: Path, monkeypatch):
    root = _build_source_tree(tmp_path)

    def fake_run_ingest(*, discovered, workers, progress, **kwargs):
        assert isinstance(progress, ProgressReporter)
        return _fake_ingest_report(len(discovered))

    def fake_run_aux_ingest(case_dir, sources, *, classified, workers, progress, **kwargs):
        assert isinstance(progress, ProgressReporter)
        return _fake_aux_report(len(classified))

    monkeypatch.setattr(case_module, "run_ingest", fake_run_ingest)
    monkeypatch.setattr(case_module, "run_aux_ingest", fake_run_aux_ingest)

    updates: list[dict] = []
    c = Case.create("c", case_root=tmp_path / "cases")
    c.ingest([str(root)], on_progress=updates.append)

    assert updates
    assert updates[-1]["phase"] == "done"
