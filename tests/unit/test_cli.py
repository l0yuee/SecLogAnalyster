from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from seclogx.case import Case
from seclogx.cli.main import app

runner = CliRunner()


def test_case_init_list_info(tmp_path: Path):
    case_root = tmp_path / "cases"

    result = runner.invoke(app, ["case", "init", "mycase", "--dir", str(case_root)])
    assert result.exit_code == 0, result.output
    assert (case_root / "mycase" / "case.json").exists()

    result = runner.invoke(app, ["case", "list", "--dir", str(case_root)])
    assert result.exit_code == 0
    assert "mycase" in result.output

    result = runner.invoke(app, ["case", "info", "mycase", "--dir", str(case_root)])
    assert result.exit_code == 0
    assert "mycase" in result.output


def test_case_init_twice_fails(tmp_path: Path):
    case_root = tmp_path / "cases"
    runner.invoke(app, ["case", "init", "dup", "--dir", str(case_root)])
    result = runner.invoke(app, ["case", "init", "dup", "--dir", str(case_root)])
    assert result.exit_code != 0


def test_query_and_summary_against_real_case(synth_case: Case):
    case_root = synth_case.case_dir.parent

    result = runner.invoke(app, ["summary", synth_case.name, "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        app,
        ["query", synth_case.name, "SELECT count(*) AS n FROM events", "--case-root", str(case_root)],
    )
    assert result.exit_code == 0, result.output


def test_hunt_cli(synth_case: Case):
    case_root = synth_case.case_dir.parent
    result = runner.invoke(app, ["hunt", synth_case.name, "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "Mimikatz" in result.output


def test_query_out_streams_full_result_to_csv(synth_case: Case, tmp_path: Path):
    """The --out path streams via chunked fetch rather than materializing
    the whole result first -- verify the written CSV still has every row."""
    case_root = synth_case.case_dir.parent
    out = tmp_path / "out.csv"
    result = runner.invoke(
        app,
        ["query", synth_case.name, "SELECT * FROM events ORDER BY record_id", "--out", str(out), "--case-root", str(case_root)],
    )
    assert result.exit_code == 0, result.output
    assert "wrote 2 rows" in result.output
    lines = out.read_text().splitlines()
    assert len(lines) == 3  # header + 2 data rows


def test_query_limit_is_pushed_into_sql(synth_case: Case):
    case_root = synth_case.case_dir.parent
    out_all = case_root.parent / "all.csv"
    result = runner.invoke(
        app,
        ["query", synth_case.name, "SELECT * FROM events", "--limit", "1", "--out", str(out_all), "--case-root", str(case_root)],
    )
    assert result.exit_code == 0, result.output
    assert "wrote 1 rows" in result.output


def test_table_command(synth_case: Case):
    case_root = synth_case.case_dir.parent
    result = runner.invoke(app, ["table", synth_case.name, "events", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(app, ["table", synth_case.name, "no_such_table", "--case-root", str(case_root)])
    assert result.exit_code != 0


def test_sources_command(synth_case: Case):
    case_root = synth_case.case_dir.parent
    result = runner.invoke(app, ["sources", synth_case.name, "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "events" in result.output


def test_search_command_contains_and_out(synth_case: Case, tmp_path: Path):
    case_root = synth_case.case_dir.parent
    out = tmp_path / "hits.csv"
    result = runner.invoke(
        app,
        ["search", synth_case.name, "events", "--contains", "Image=mimikatz", "--out", str(out), "--case-root", str(case_root)],
    )
    assert result.exit_code == 0, result.output
    assert "wrote 1 rows" in result.output
    assert len(out.read_text().splitlines()) == 2  # header + 1 row


def test_search_command_unknown_field_reports_cleanly(tmp_path: Path):
    from seclogx.discovery import SourceSpec
    from seclogx.logsources.ingest import run_aux_ingest

    fixtures = Path(__file__).parent.parent / "fixtures" / "logsources"
    case = Case.create("clisearchfields", case_root=tmp_path / "cases")
    run_aux_ingest(case.case_dir, [SourceSpec(path=fixtures, host="LAB01")], workers=1)

    result = runner.invoke(
        app, ["search", "clisearchfields", "scheduled_tasks", "--eq", "bogus=1", "--case-root", str(tmp_path / "cases")]
    )
    assert result.exit_code != 0
    assert "not a column" in result.output


def test_fields_command(synth_case: Case):
    case_root = synth_case.case_dir.parent
    result = runner.invoke(app, ["fields", synth_case.name, "events", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "Image" in result.output

    result = runner.invoke(app, ["fields", synth_case.name, "no_such_table", "--case-root", str(case_root)])
    assert result.exit_code != 0


def test_search_command_no_matches(synth_case: Case):
    case_root = synth_case.case_dir.parent
    result = runner.invoke(
        app, ["search", synth_case.name, "events", "--eq", "host=NOPE", "--case-root", str(case_root)]
    )
    assert result.exit_code == 0, result.output
    assert "no rows matched" in result.output
