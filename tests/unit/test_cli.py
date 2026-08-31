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
    from seclogx.ingest.common import SourceSpec
    from seclogx.ingest.logsources.orchestrator import run_aux_ingest

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


def test_timeline_command(synth_case: Case, tmp_path: Path):
    case_root = synth_case.case_dir.parent

    result = runner.invoke(app, ["timeline", synth_case.name, "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output

    out = tmp_path / "timeline.csv"
    result = runner.invoke(
        app,
        ["timeline", synth_case.name, "--host", "TESTHOST", "--event-id", "1", "--out", str(out), "--case-root", str(case_root)],
    )
    assert result.exit_code == 0, result.output
    assert "wrote 2 rows" in result.output
    assert len(out.read_text().splitlines()) == 3  # header + 2 rows

    # a case with no events table exits cleanly with a warning, not a crash
    from seclogx.case import Case

    empty = Case.create("notimeline", case_root=case_root)
    result = runner.invoke(app, ["timeline", empty.name, "--case-root", str(case_root)])
    assert result.exit_code != 0
    assert "no ingested Windows Event Log data" in result.output


def test_tasks_command(tmp_path: Path):
    from seclogx.ingest.common import SourceSpec
    from seclogx.ingest.logsources.orchestrator import run_aux_ingest

    fixtures = Path(__file__).parent.parent / "fixtures" / "logsources"
    case_root = tmp_path / "cases"
    case = Case.create("clitasks", case_root=case_root)
    run_aux_ingest(case.case_dir, [SourceSpec(path=fixtures, host="LAB01")], workers=1)

    result = runner.invoke(app, ["tasks", "clitasks", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "Scheduled tasks" in result.output

    result = runner.invoke(app, ["tasks", "clitasks", "--suspicious", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output

    # a case with no scheduled_tasks table exits cleanly with a warning
    empty = Case.create("notasks", case_root=case_root)
    result = runner.invoke(app, ["tasks", empty.name, "--case-root", str(case_root)])
    assert result.exit_code != 0
    assert "no scheduled task definitions" in result.output


def test_auth_command(tmp_path: Path):
    from seclogx.ingest.common import SourceSpec
    from seclogx.ingest.logsources.orchestrator import run_aux_ingest

    fixtures = Path(__file__).parent.parent / "fixtures" / "logsources_linux"
    case_root = tmp_path / "cases"
    case = Case.create("cliauth", case_root=case_root)
    run_aux_ingest(case.case_dir, [SourceSpec(path=fixtures, host="LAB01")], workers=1)

    result = runner.invoke(app, ["auth", "cliauth", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "Auth events" in result.output

    out = tmp_path / "auth.csv"
    result = runner.invoke(app, ["auth", "cliauth", "--out", str(out), "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    assert "wrote 8 rows" in result.output

    # a case with no syslog table exits cleanly with a warning
    empty = Case.create("noauth", case_root=case_root)
    result = runner.invoke(app, ["auth", empty.name, "--case-root", str(case_root)])
    assert result.exit_code != 0
    assert "no syslog data ingested" in result.output


def test_rules_validate_command():
    result = runner.invoke(app, ["rules", "validate"])
    assert result.exit_code == 0, result.output
    assert "rules convert successfully" in result.output
    assert "0 failed conversion" in result.output


def test_rules_validate_command_with_custom_dir(tmp_path: Path):
    result = runner.invoke(app, ["rules", "validate", "--rules", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "0 rules convert successfully" in result.output


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip()
