"""Coverage of the analyst-facing automatic ingest policy."""
from __future__ import annotations

from dataclasses import replace
import os
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from seclogx import Case, IngestOptions
from seclogx.cli.main import app
from seclogx.distributed.config import ClusterConfig
from seclogx.ingest.logsources import orchestrator
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.sniff import KIND_IIS, KIND_WEB_ACCESS


def _sources(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "nginx_access.log").write_text(
        '192.0.2.1 - alice [19/Sep/2026:08:12:34 +0800] "GET /default HTTP/1.1" 200 12 "-" "UA"\n',
        encoding="utf-8",
    )
    (root / "iis.log").write_text(
        "#Software: Microsoft Internet Information Services\n"
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes\n"
        "2026-09-19 08:12:34 192.0.2.2 GET /iis 200 12\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize("backend", ["auto", "python", "native"])
@pytest.mark.parametrize("keep_staging,config,eligible", [
    (False, ClusterConfig.local(), True),
    (True, ClusterConfig.local(), False),
    (False, ClusterConfig(broker_url="redis://unused"), False),
    (False, ClusterConfig(storage_backend="s3", s3_bucket="unused"), False),
])
def test_automatic_options_resolve_from_execution_context_without_mutation(backend, keep_staging, config, eligible):
    options = IngestOptions(parser_backend=backend)
    resolved = options.resolve_execution(keep_staging=keep_staging, cluster_config=config)
    assert options.direct_parquet is None
    assert resolved.direct_parquet is (eligible and backend != "python")
    assert replace(resolved, direct_parquet=None) == options
    assert resolved.resolve_execution(keep_staging=keep_staging, cluster_config=config) is resolved


@pytest.mark.parametrize("direct", [True, False])
def test_explicit_output_override_is_preserved(direct):
    options = IngestOptions(direct_parquet=direct)
    assert options.resolve_execution(keep_staging=False, cluster_config=ClusterConfig.local()) is options


def test_case_without_tuning_uses_native_direct_and_removes_staging(tmp_path):
    pytest.importorskip("seclogx._native_backend")
    source = _sources(tmp_path)
    case = Case.create("automatic", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    report = case.ingest([str(source)])
    assert report.aux.files_ok == 2
    assert report.aux.rows_written == {"web_logs": 2}
    assert all(item.parser_backend == "native" and item.output_format == "parquet"
               for item in report.aux.staged_files)
    assert all(item.parquet_paths and not item.chunks for item in report.aux.staged_files)
    assert not list((case.case_dir / "staging_aux").rglob("*.arrow"))
    assert not list((case.case_dir / "staging_aux").rglob("*.gz"))
    with case:
        assert case.query("SELECT count(*) AS n FROM web_logs")["n"].iloc[0] == 2


@pytest.mark.parametrize("options,keep_staging", [
    (IngestOptions(parser_backend="python"), False),
    (IngestOptions(direct_parquet=False), False),
    (IngestOptions(), True),
])
def test_case_explicit_compatibility_choices_remain_usable(tmp_path, options, keep_staging):
    source = _sources(tmp_path)
    case = Case.create("compatibility", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    report = case.ingest([str(source)], workers=1, keep_staging=keep_staging, options=options)
    assert report.aux.rows_written == {"web_logs": 2}
    assert all(item.output_format == "staged" and item.chunks for item in report.aux.staged_files)
    assert all(item.parser_backend == "python" for item in report.aux.staged_files)
    assert all(Path(chunk.path).exists() is keep_staging
               for item in report.aux.staged_files for chunk in item.chunks)


def test_missing_native_routes_every_web_file_through_normal_worker_queue(tmp_path, monkeypatch):
    source = _sources(tmp_path)
    monkeypatch.setitem(sys.modules, "seclogx._native_backend", None)
    classified = [ClassifiedFile(path, "HOST", path.stat().st_size,
                                KIND_IIS if path.name == "iis.log" else KIND_WEB_ACCESS)
                  for path in sorted(source.iterdir())]
    queued = []

    class Queue:
        def submit_all(self, fn, args_list, on_result=None):
            queued.extend(args[0] for args in args_list)
            return [fn(*args) for args in args_list]

    def queue(config, *, workers, queue_name):
        assert workers == 4
        return Queue()

    def no_direct(*args, **kwargs):
        pytest.fail("missing native must preserve parallel staging, not serialize per-source replay")

    monkeypatch.setattr(orchestrator, "get_job_queue", queue)
    monkeypatch.setattr("seclogx.ingest.logsources.direct.direct_web_file", no_direct)
    report = orchestrator.run_aux_ingest(tmp_path / "case", [], workers=4,
                                         classified=classified, cluster_config=ClusterConfig.local())
    assert queued == classified
    assert report.rows_written == {"web_logs": 2}
    assert all(item.parser_backend == "python" and item.output_format == "staged"
               for item in report.staged_files)


@pytest.mark.parametrize("config", [ClusterConfig(broker_url="redis://unused"),
                                    ClusterConfig(storage_backend="s3", s3_bucket="unused")])
def test_nonlocal_defaults_keep_web_work_on_configured_staging_queue(tmp_path, monkeypatch, config):
    source = _sources(tmp_path)
    classified = [ClassifiedFile(path, "HOST", path.stat().st_size,
                                KIND_IIS if path.name == "iis.log" else KIND_WEB_ACCESS)
                  for path in sorted(source.iterdir())]
    queued = []

    class Queue:
        def submit_all(self, fn, args_list, on_result=None):
            assert all(args[2].direct_parquet is False for args in args_list)
            queued.extend(args[0] for args in args_list)
            return [fn(*args) for args in args_list]

    def queue(received_config, *, workers, queue_name):
        assert received_config is config
        return Queue()

    def no_direct(*args, **kwargs):
        pytest.fail("nonlocal automatic execution must not attempt local direct conversion")

    monkeypatch.setattr(orchestrator, "get_job_queue", queue)
    monkeypatch.setattr(orchestrator, "flatten_table", lambda *args, **kwargs: 2)
    monkeypatch.setattr("seclogx.ingest.logsources.direct.direct_web_file", no_direct)
    monkeypatch.setattr("seclogx.ingest.logsources.native.load_native_component", no_direct)
    report = orchestrator.run_aux_ingest(tmp_path / "case", [], classified=classified, cluster_config=config)
    assert queued == classified
    assert report.rows_written == {"web_logs": 2}


@pytest.mark.parametrize("direct,flag", [(None, None), (True, "--direct-parquet"), (False, "--no-direct-parquet")])
def test_background_preserves_automatic_or_explicit_output_choice(tmp_path, monkeypatch, direct, flag):
    commands = []
    monkeypatch.setattr("seclogx.case.subprocess.Popen", lambda args, **kwargs: commands.append(args))
    case = Case.create("background", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    case.ingest_background([str(tmp_path / "source")], options=IngestOptions(direct_parquet=direct))
    args = commands[0]
    assert "--no-keep-staging" in args
    assert args[args.index("--parser-backend") + 1] == "auto"
    assert ("--direct-parquet" in args) is (flag == "--direct-parquet")
    assert ("--no-direct-parquet" in args) is (flag == "--no-direct-parquet")


@pytest.mark.parametrize("config", [
    None,
    ClusterConfig.local(),
    ClusterConfig(storage_backend="s3", s3_bucket="instance-bucket",
                  s3_endpoint_url="https://instance.invalid", s3_region="instance-region",
                  broker_url="redis://instance.invalid"),
])
def test_background_passes_resolved_case_configuration_without_mutating_parent(tmp_path, monkeypatch, config):
    inherited = {
        "SECLOGX_STORAGE_BACKEND": "s3",
        "SECLOGX_S3_BUCKET": "parent-bucket",
        "SECLOGX_S3_ENDPOINT_URL": "https://parent.invalid",
        "SECLOGX_S3_REGION": "parent-region",
        "SECLOGX_BROKER_URL": "redis://parent.invalid",
        "AWS_PROFILE": "preserved-profile",
        "ANALYST_SESSION_SETTING": "preserved-value",
    }
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)
    before = dict(os.environ)
    calls = []
    monkeypatch.setattr("seclogx.case.subprocess.Popen", lambda args, **kwargs: calls.append((args, kwargs)))
    case = Case.create("configured-background", case_root=tmp_path / "cases", cluster_config=config)
    job_id = case.ingest_background([str(tmp_path / "source")])
    assert dict(os.environ) == before
    assert len(calls) == 1
    args, kwargs = calls[0]
    expected = case.cluster_config
    child_env = kwargs["env"]
    assert child_env is not os.environ
    for name, value in {
        "SECLOGX_STORAGE_BACKEND": expected.storage_backend,
        "SECLOGX_S3_BUCKET": expected.s3_bucket,
        "SECLOGX_S3_ENDPOINT_URL": expected.s3_endpoint_url,
        "SECLOGX_S3_REGION": expected.s3_region,
        "SECLOGX_BROKER_URL": expected.broker_url,
    }.items():
        if value is None:
            assert name not in child_env
        else:
            assert child_env[name] == value
            assert value not in args
    assert child_env["AWS_PROFILE"] == "preserved-profile"
    assert child_env["ANALYST_SESSION_SETTING"] == "preserved-value"
    assert case.job_status(job_id).get("cluster_config") is None


def test_default_background_child_produces_queryable_native_output(tmp_path):
    pytest.importorskip("seclogx._native_backend")
    source = _sources(tmp_path)
    case = Case.create("background-real", case_root=tmp_path / "cases", cluster_config=ClusterConfig.local())
    job_id = case.ingest_background([str(source)])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = case.job_status(job_id)
        if status and status.get("phase") in {"done", "failed"}:
            break
        time.sleep(0.1)
    assert status["phase"] == "done", status
    assert status["rows_written"] == {"web_logs": 2}
    assert not list((case.case_dir / "staging_aux").rglob("*.arrow"))
    assert not list((case.case_dir / "staging_aux").rglob("*.gz"))
    with case:
        assert case.query("SELECT count(*) AS n FROM web_logs")["n"].iloc[0] == 2


@pytest.mark.parametrize("flags,direct,keep_staging,backend", [
    ([], None, False, "auto"),
    (["--direct-parquet"], True, False, "auto"),
    (["--no-direct-parquet"], False, False, "auto"),
    (["--keep-staging"], None, True, "auto"),
    (["--parser-backend", "python"], None, False, "python"),
])
def test_cli_preserves_automatic_defaults_and_explicit_overrides(tmp_path, monkeypatch, flags, direct, keep_staging, backend):
    calls = []
    monkeypatch.setattr("seclogx.cli.ingest_cmd._run_in_foreground", lambda *args: calls.append(args))
    result = CliRunner().invoke(app, ["ingest", "cli", "--source", str(tmp_path / "source"),
                                    "--case-root", str(tmp_path / "cases"), *flags])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0][-2] is keep_staging
    assert calls[0][-1].direct_parquet is direct
    assert calls[0][-1].parser_backend == backend
