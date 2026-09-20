"""Direct fallback/source and public-option boundaries."""
from __future__ import annotations

import dataclasses
import pytest
from typer.testing import CliRunner

from seclogx import Case
from seclogx.cli.main import app
from seclogx.distributed.config import ClusterConfig
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.sniff import KIND_WEB_ACCESS
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.ingest.resources import IngestOptions
from seclogx.textdecode import SourceChangedError, prepare_text


def _prepared(tmp_path):
    path = tmp_path / "access.log"
    path.write_text('192.0.2.1 - - [17/Sep/2026:08:12:34 +0800] "GET /original HTTP/1.1" 200 42\n')
    return ClassifiedFile(path, "HOST", path.stat().st_size, KIND_WEB_ACCESS), prepare_text(path)


def test_fallback_reuses_original_prepared_hash(tmp_path, monkeypatch):
    cf, prepared = _prepared(tmp_path)
    def unexpected(*args, **kwargs):
        raise AssertionError("must not prepare the source again")
    monkeypatch.setattr("seclogx.ingest.logsources.stage.prepare_text", unexpected)
    result = stage_aux_file(cf, tmp_path / "staging", IngestOptions(parser_backend="python"), prepared=prepared)
    assert result.record_count == 1
    assert result.file_sha256 == prepared.sha256


def test_changed_prepared_source_is_fatal_before_fallback(tmp_path):
    cf, prepared = _prepared(tmp_path)
    cf.path.write_text("replaced")
    with pytest.raises(SourceChangedError):
        stage_aux_file(cf, tmp_path / "staging", IngestOptions(parser_backend="python"), prepared=prepared)
    assert not (tmp_path / "staging").exists()


@pytest.mark.parametrize("change", ["path", "policy"])
def test_prepared_source_must_match_fallback_identity_and_policy(tmp_path, change):
    cf, prepared = _prepared(tmp_path)
    prepared = dataclasses.replace(prepared, **({"path": tmp_path / "another.log"} if change == "path" else {"utf16_requires_bom": True}))
    with pytest.raises(ValueError, match="prepared source"):
        stage_aux_file(cf, tmp_path / "staging", prepared=prepared)


@pytest.mark.parametrize("value", [1, "true", [], {}])
def test_direct_option_requires_boolean_or_none(value):
    with pytest.raises(ValueError, match="direct_parquet"):
        IngestOptions(parser_backend="auto", direct_parquet=value)


def test_direct_python_conflict_is_explicit():
    with pytest.raises(ValueError, match="parser_backend"):
        IngestOptions(direct_parquet=True, parser_backend="python")


@pytest.mark.parametrize("background", [False, True])
@pytest.mark.parametrize("config,keep_staging", [
    (ClusterConfig.local(), True),
    (ClusterConfig(storage_backend="s3", s3_bucket="unused"), False),
    (ClusterConfig(broker_url="redis://unused"), False),
])
def test_case_rejects_direct_conflict_before_scan_or_job_creation(tmp_path, background, config, keep_staging):
    case = Case.create("case", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    case.cluster_config = config
    method = case.ingest_background if background else case.ingest
    with pytest.raises(ValueError, match="direct_parquet"):
        method([str(tmp_path / "missing")], keep_staging=keep_staging, options=IngestOptions(parser_backend="auto", direct_parquet=True))
    assert not list(case.case_dir.rglob("*.parquet"))
    assert not (case.case_dir / "jobs").exists()


def test_background_forwards_direct_mode(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr("seclogx.case.subprocess.Popen", lambda args, **kwargs: commands.append(args))
    case = Case.create("case", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    case.ingest_background([str(tmp_path / "source")], keep_staging=False, options=IngestOptions(parser_backend="auto", direct_parquet=True))
    assert "--direct-parquet" in commands[0]
    assert "--no-keep-staging" in commands[0]


def test_cli_rejects_retained_direct_output_before_creating_case(tmp_path):
    result = CliRunner().invoke(app, ["ingest", "invalid", "--source", str(tmp_path),
                                    "--case-root", str(tmp_path / "cases"), "--parser-backend", "auto", "--direct-parquet", "--keep-staging"])
    assert result.exit_code == 2
    assert "--no-keep-staging" in result.output
    assert not (tmp_path / "cases").exists()
