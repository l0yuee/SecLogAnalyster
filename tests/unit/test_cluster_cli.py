from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from seclogx.cli.main import app

runner = CliRunner()


def test_cluster_config_reports_local_by_default(monkeypatch):
    for var in ("SECLOGX_STORAGE_BACKEND", "SECLOGX_S3_BUCKET", "SECLOGX_BROKER_URL"):
        monkeypatch.delenv(var, raising=False)
    result = runner.invoke(app, ["cluster", "config"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data == {
        "storage_backend": "local",
        "s3_bucket": None,
        "s3_endpoint_url": None,
        "s3_region": None,
        "broker_url": None,
        "is_distributed": False,
    }


def test_cluster_config_reflects_env_vars(monkeypatch):
    monkeypatch.setenv("SECLOGX_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("SECLOGX_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("SECLOGX_BROKER_URL", "redis://broker:6379/0")
    result = runner.invoke(app, ["cluster", "config"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["storage_backend"] == "s3"
    assert data["s3_bucket"] == "my-bucket"
    assert data["is_distributed"] is True


def test_cluster_status_without_broker_configured(monkeypatch):
    monkeypatch.delenv("SECLOGX_BROKER_URL", raising=False)
    result = runner.invoke(app, ["cluster", "status"])
    assert result.exit_code == 0, result.output
    assert "no SECLOGX_BROKER_URL configured" in result.output


def test_cluster_status_with_broker_configured(monkeypatch):
    pytest.importorskip("fakeredis")
    import fakeredis
    import redis

    conn = fakeredis.FakeStrictRedis()
    monkeypatch.setattr(redis, "from_url", lambda *_a, **_k: conn)
    monkeypatch.setenv("SECLOGX_BROKER_URL", "redis://fake")

    result = runner.invoke(app, ["cluster", "status"])
    assert result.exit_code == 0, result.output
    assert "workers online: 0" in result.output
    assert "queue 'seclogx-ingest': 0 pending" in result.output
    assert "queue 'seclogx-hunt': 0 pending" in result.output


def test_worker_command_requires_broker(monkeypatch):
    monkeypatch.delenv("SECLOGX_BROKER_URL", raising=False)
    result = runner.invoke(app, ["worker"])
    assert result.exit_code != 0
    assert "SECLOGX_BROKER_URL is not set" in result.output
