from __future__ import annotations

from seclogx.ingest.common import StageStatus
from seclogx.ingest.evtx.manifest import IngestReport, StagedFile
from seclogx.ingest.logsources.manifest import AuxIngestReport, AuxStagedFile


def _staged_file(status: str, record_count: int, error_message=None) -> StagedFile:
    return StagedFile(
        source_path=f"/evidence/{status}.evtx",
        source_file=f"{status}.evtx",
        host="WKS01",
        file_sha256="0" * 64,
        size_bytes=1024,
        status=status,
        record_count=record_count,
        error_count=0,
        error_message=error_message,
        ndjson_path=None,
        staged_at="2026-01-01T00:00:00+00:00",
    )


def test_ingest_report_to_dataframe_one_row_per_file():
    report = IngestReport(
        batch_id="batch1",
        case_name="incident42",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        files_discovered=2,
        files_ok=1,
        files_partial=1,
        files_failed=0,
        records_staged=150,
        records_flattened=150,
        staged_files=[_staged_file(StageStatus.OK, 100), _staged_file(StageStatus.PARTIAL, 50, "bad chunk")],
    )

    df = report.to_dataframe()
    assert len(df) == 2
    assert set(df["status"]) == {StageStatus.OK, StageStatus.PARTIAL}
    assert df["record_count"].sum() == 150


def test_ingest_report_summary_text_reports_counts_and_problems():
    report = IngestReport(
        batch_id="batch1",
        case_name="incident42",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        files_discovered=2,
        files_ok=1,
        files_partial=1,
        files_failed=0,
        records_staged=150,
        records_flattened=150,
        staged_files=[_staged_file(StageStatus.OK, 100), _staged_file(StageStatus.PARTIAL, 50, "bad chunk")],
    )

    text = report.summary_text()
    assert "incident42" in text
    assert "files ok         : 1" in text
    assert "files partial    : 1" in text
    assert "bad chunk" in text  # per-file error surfaced, never swallowed


def test_ingest_report_summary_text_warns_on_staged_flattened_mismatch():
    report = IngestReport(
        batch_id="batch1",
        case_name="incident42",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        files_discovered=1,
        files_ok=1,
        files_partial=0,
        files_failed=0,
        records_staged=100,
        records_flattened=90,  # deliberately mismatched
        staged_files=[_staged_file(StageStatus.OK, 100)],
    )

    assert "WARNING" in report.summary_text()


def test_ingest_report_embeds_aux_report_summary():
    aux = AuxIngestReport(
        batch_id="batch1",
        files_discovered=1,
        files_ok=1,
        files_partial=0,
        files_failed=0,
        files_unknown=0,
        unknown_samples=[],
        rows_written={"web_logs": 4},
        problem_files=[],
    )
    report = IngestReport(
        batch_id="batch1",
        case_name="incident42",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        files_discovered=0,
        files_ok=0,
        files_partial=0,
        files_failed=0,
        records_staged=0,
        records_flattened=0,
        staged_files=[],
        aux=aux,
    )

    text = report.summary_text()
    assert "web_logs: 4" in text


def _aux_staged_file(status: str, table: str | None = "scheduled_tasks", error_message=None) -> AuxStagedFile:
    return AuxStagedFile(
        source_path=f"/evidence/{status}.xml",
        source_file=f"{status}.xml",
        host="WKS01",
        file_sha256="1" * 64,
        size_bytes=512,
        kind="scheduled_task",
        table=table,
        status=status,
        record_count=1 if status == StageStatus.OK else 0,
        error_count=0,
        error_message=error_message,
        ndjson_path=None,
        staged_at="2026-01-01T00:00:00+00:00",
    )


def test_aux_ingest_report_to_dataframe_one_row_per_file():
    report = AuxIngestReport(
        batch_id="batch1",
        files_discovered=1,
        files_ok=1,
        files_partial=0,
        files_failed=0,
        files_unknown=0,
        unknown_samples=[],
        rows_written={"scheduled_tasks": 1},
        problem_files=[],
        staged_files=[_aux_staged_file(StageStatus.OK)],
    )

    df = report.to_dataframe()
    assert "ndjson_path" in df.columns
    assert len(df) == 1
    assert df.iloc[0]["status"] == StageStatus.OK


def test_aux_ingest_report_summary_text_lists_unknown_and_problem_files():
    report = AuxIngestReport(
        batch_id="batch1",
        files_discovered=2,
        files_ok=0,
        files_partial=0,
        files_failed=1,
        files_unknown=1,
        unknown_samples=["/evidence/notes.txt"],
        rows_written={},
        problem_files=[("/evidence/broken.xml", StageStatus.FAILED, "malformed XML")],
    )

    text = report.summary_text()
    assert "files unrecognized: 1" in text
    assert "/evidence/notes.txt" in text
    assert "malformed XML" in text


def test_aux_ingest_report_empty_batch_summary_has_no_rows_written_section():
    report = AuxIngestReport(
        batch_id="batch1",
        files_discovered=0,
        files_ok=0,
        files_partial=0,
        files_failed=0,
        files_unknown=0,
        unknown_samples=[],
        rows_written={},
        problem_files=[],
    )
    text = report.summary_text()
    assert "rows written per table" not in text
