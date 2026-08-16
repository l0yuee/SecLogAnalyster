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
