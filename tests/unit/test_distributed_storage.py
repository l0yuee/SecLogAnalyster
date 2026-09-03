from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.storage import (
    LocalStorageBackend,
    S3StorageBackend,
    ensure_hive_partition_dirs,
    get_storage_backend,
)
from seclogx.errors import ClusterConfigError


def _make_local_lake(tmp_path: Path) -> Path:
    case_dir = tmp_path / "cases" / "c1"
    lake = case_dir / "lake"
    (lake / "syslog" / "host=LAB01").mkdir(parents=True)
    (lake / "syslog" / "host=LAB01" / "a.parquet").write_bytes(b"")
    (lake / "syslog" / "host=LAB02").mkdir(parents=True)
    (lake / "syslog" / "host=LAB02" / "b.parquet").write_bytes(b"")
    (lake / "empty_table").mkdir(parents=True)  # no parquet inside -- has_parquet should say no
    return case_dir


class TestLocalStorageBackend:
    """LocalStorageBackend must behave exactly like the raw `pathlib` code
    it replaced in CaseDB/Case -- see distributed/storage.py's docstring."""

    def test_get_storage_backend_default_is_local(self):
        assert isinstance(get_storage_backend(ClusterConfig.local()), LocalStorageBackend)

    def test_table_dirs_and_has_parquet(self, tmp_path):
        case_dir = _make_local_lake(tmp_path)
        backend = LocalStorageBackend()
        lake_location = backend.lake_location(case_dir)
        assert set(backend.table_dirs(lake_location)) == {"syslog", "empty_table"}
        assert backend.has_parquet(backend.table_location(case_dir, "syslog"))
        assert not backend.has_parquet(backend.table_location(case_dir, "empty_table"))

    def test_host_partitions_percent_decoded(self, tmp_path):
        case_dir = _make_local_lake(tmp_path)
        backend = LocalStorageBackend()
        weird = case_dir / "lake" / "syslog" / "host=lab%2003"  # %20 -> space
        weird.mkdir()
        (weird / "c.parquet").write_bytes(b"")
        hosts = backend.host_partitions(backend.table_location(case_dir, "syslog"))
        assert hosts == {"LAB01", "LAB02", "lab 03"}

    def test_exists_false_for_missing_lake(self, tmp_path):
        backend = LocalStorageBackend()
        assert not backend.exists(backend.lake_location(tmp_path / "cases" / "nope"))

    def test_ensure_dir_creates_directory(self, tmp_path):
        backend = LocalStorageBackend()
        loc = backend.table_location(tmp_path / "cases" / "c1", "web_logs")
        assert not Path(loc).exists()
        backend.ensure_dir(loc)
        assert Path(loc).is_dir()

    def test_parquet_glob_and_copy_target(self, tmp_path):
        case_dir = _make_local_lake(tmp_path)
        backend = LocalStorageBackend()
        loc = backend.table_location(case_dir, "syslog")
        assert backend.parquet_glob(loc) == str(Path(loc) / "**" / "*.parquet")
        assert backend.copy_target(loc) == loc

    def test_ensure_hive_partition_dirs_matches_duckdb_encoding(self, tmp_path):
        backend = LocalStorageBackend()
        table = backend.table_location(tmp_path / "cases" / "c1", "events")
        ensure_hive_partition_dirs(
            backend,
            table,
            ("host", "channel"),
            [("lab 03", "Microsoft-Windows/Sysmon"), ("中文", None)],
        )
        assert (Path(table) / "host=lab%2003" / "channel=Microsoft-Windows%2FSysmon").is_dir()
        assert (Path(table) / "host=%E4%B8%AD%E6%96%87" / "channel=__HIVE_DEFAULT_PARTITION__").is_dir()

    def test_configure_duckdb_is_a_noop(self):
        con = duckdb.connect()
        LocalStorageBackend().configure_duckdb(con)  # must not raise
        con.close()


class TestS3StorageBackend:
    """Metadata operations (existence/listing/host-partition decoding) go
    through boto3, tested here via moto's `mock_aws()`. The actual
    DuckDB<->S3 Parquet read/write goes through DuckDB's own `httpfs`
    extension, which isn't intercepted by `mock_aws()` (it only patches
    boto3/botocore, not DuckDB's native HTTP client) -- that path was
    verified manually end-to-end against a real local S3-compatible
    server during implementation; see docs/guides/10_distributed_deployment.md."""

    @pytest.fixture
    def s3_bucket(self, monkeypatch):
        moto = pytest.importorskip("moto")
        with moto.mock_aws():
            import boto3

            monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
            monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
            monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
            client = boto3.client("s3", region_name="us-east-1")
            client.create_bucket(Bucket="seclogx-test")
            yield client

    @staticmethod
    def _config(**overrides) -> ClusterConfig:
        base = dict(storage_backend="s3", s3_bucket="seclogx-test", s3_region="us-east-1")
        base.update(overrides)
        return ClusterConfig(**base)

    def test_requires_bucket(self):
        with pytest.raises(ClusterConfigError):
            S3StorageBackend(ClusterConfig(storage_backend="s3"))

    def test_lake_location_keyed_by_case_name(self, s3_bucket):
        backend = S3StorageBackend(self._config())
        loc = backend.lake_location(Path("/anywhere/cases/incident42"))
        assert loc == "s3://seclogx-test/incident42/lake"

    def test_exists_table_dirs_has_parquet_host_partitions(self, s3_bucket):
        backend = S3StorageBackend(self._config())
        case_dir = Path("/x/cases/incident42")
        lake = backend.lake_location(case_dir)
        assert not backend.exists(lake)

        s3_bucket.put_object(
            Bucket="seclogx-test",
            Key="incident42/lake/syslog/host=LAB01/00000000-0000-0000-0000-000000000000.parquet",
            Body=b"stand-in bytes -- only key listing is exercised here, not real Parquet content",
        )
        assert backend.exists(lake)
        assert backend.table_dirs(lake) == ["syslog"]
        table_loc = backend.table_location(case_dir, "syslog")
        assert backend.has_parquet(table_loc)
        assert backend.host_partitions(table_loc) == {"LAB01"}

    def test_has_parquet_false_when_prefix_has_no_parquet_objects(self, s3_bucket):
        backend = S3StorageBackend(self._config())
        case_dir = Path("/x/cases/incident42")
        s3_bucket.put_object(Bucket="seclogx-test", Key="incident42/lake/syslog/host=LAB01/README.txt", Body=b"x")
        table_loc = backend.table_location(case_dir, "syslog")
        assert not backend.has_parquet(table_loc)

    def test_configure_duckdb_sets_s3_pragmas(self, s3_bucket):
        backend = S3StorageBackend(self._config(s3_endpoint_url="http://127.0.0.1:9999"))

        # Keep this a deterministic unit test: INSTALL httpfs otherwise
        # writes to the user's DuckDB extension directory and may access the
        # network. The real S3 integration path is documented as a manual
        # end-to-end test in this class's docstring.
        class RecordingConnection:
            def __init__(self):
                self.calls = []

            def execute(self, query, parameters=None):
                self.calls.append((query, parameters))
                return self

        con = RecordingConnection()
        backend.configure_duckdb(con)
        assert ("INSTALL httpfs", None) in con.calls
        assert ("LOAD httpfs", None) in con.calls
        assert ("SET s3_region=?", ["us-east-1"]) in con.calls
        assert ("SET s3_endpoint=?", ["127.0.0.1:9999"]) in con.calls
        assert ("SET s3_access_key_id=?", ["testing"]) in con.calls
        assert ("SET s3_secret_access_key=?", ["testing"]) in con.calls
        assert ("SET s3_use_ssl=?", [False]) in con.calls
        assert ("SET s3_url_style='path'", None) in con.calls

    def test_get_storage_backend_returns_s3_when_configured(self, s3_bucket):
        assert isinstance(get_storage_backend(self._config()), S3StorageBackend)
