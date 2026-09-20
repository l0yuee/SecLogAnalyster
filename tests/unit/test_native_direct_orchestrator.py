"""Local regression coverage for the optional single-lane direct coordinator."""

from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from seclogx.distributed.config import ClusterConfig
from seclogx.ingest.common import StageStatus
from seclogx.ingest.logsources import orchestrator
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.manifest import AuxStagedFile
from seclogx.ingest.logsources.native import NativeBatchError
from seclogx.ingest.logsources.sniff import KIND_IIS, KIND_SYSLOG, KIND_WEB_ACCESS
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.staging import StagedChunk, remove_staged


class Progress:
    def __init__(self):
        self.phases = []
        self.results = []
        self.rows = []

    def set_phase(self, phase):
        self.phases.append(phase)

    def on_aux_result(self, result):
        self.results.append(result)

    def on_table_flattened(self, table, rows):
        self.rows.append((table, rows))


def _manifest(cf, *, rows=0, status=StageStatus.OK, table=None, staged_path=None,
              parquet_path=None):
    return AuxStagedFile(
        source_path=str(cf.path), source_file=cf.path.name, host=cf.host,
        file_sha256="fixture-hash", size_bytes=cf.size_bytes, kind=cf.kind,
        table=table, status=status, record_count=rows,
        error_count=int(status in (StageStatus.PARTIAL, StageStatus.FAILED)),
        error_message="fixture parse failure" if status != StageStatus.OK else None,
        ndjson_path=str(staged_path) if staged_path is not None else None,
        chunks=[StagedChunk(str(staged_path), 32, rows)] if staged_path is not None else [],
        output_format="parquet" if parquet_path is not None else "staged",
        parquet_paths=[str(parquet_path)] if parquet_path is not None else [],
        parser_backend="native" if parquet_path is not None else "python",
    )


def _install_direct(monkeypatch, fn):
    module = ModuleType("seclogx.ingest.logsources.direct")
    module.direct_web_file = fn
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr("seclogx.ingest.logsources.native.load_native_component",
                        lambda: SimpleNamespace(module=object(), fallback_reason=None))


def _forbidden(*args, **kwargs):
    pytest.fail("unexpected coordinator operation")


def test_mixed_sources_close_worker_lane_before_direct_and_count_outputs_once(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    unknown = ClassifiedFile(tmp_path / "unknown.bin", "HOST", 1, None)
    syslog = ClassifiedFile(tmp_path / "auth.log", "HOST", 2, KIND_SYSLOG)
    web = ClassifiedFile(tmp_path / "nginx.log", "HOST", 3, KIND_WEB_ACCESS)
    iis = ClassifiedFile(tmp_path / "iis.log", "HOST", 4, KIND_IIS)
    classified = [web, unknown, iis, syslog]
    options = IngestOptions(parser_backend="auto", memory_limit="3GB", threads=3, staging_chunk_bytes=256,
                            flatten_batch_bytes=1024, direct_parquet=True)
    progress = Progress()
    events = []
    normal_paths = []
    published_paths = []
    direct_times = []
    direct_batch_ids = []
    queue_finished = False

    def stage(cf, staging_dir, received_options=None):
        if cf is unknown:
            return _manifest(cf, status=StageStatus.UNKNOWN)
        assert cf is syslog
        assert received_options is options
        path = staging_dir / "auth.ndjson.gz"
        path.write_bytes(b"staging fixture")
        normal_paths.append(str(path))
        return _manifest(cf, rows=2, table="linux_logs", staged_path=path)

    class Queue:
        def submit_all(self, fn, args_list, on_result=None):
            nonlocal queue_finished
            events.append("queue-start")
            assert [args[0] for args in args_list] == [syslog]
            results = [fn(*args) for args in args_list]
            for result in results:
                on_result(result)
            queue_finished = True
            events.append("queue-closed")
            return results

    def get_queue(config, *, workers, queue_name):
        assert config == ClusterConfig.local()
        assert workers == 6  # Direct work must not subtract from this lane.
        assert queue_name == orchestrator.INGEST_QUEUE_NAME
        return Queue()

    def direct(cf, received_case, batch_id, ingested_at, received_options, *, prepared=None):
        assert queue_finished
        assert received_case == case_dir
        assert received_options is options
        assert prepared is None
        events.append(f"direct:{cf.kind}")
        direct_times.append(ingested_at)
        direct_batch_ids.append(batch_id)
        path = case_dir / "lake" / "web_logs" / f"{cf.kind}.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"published fixture")
        published_paths.append(path)
        rows = 3 if cf is web else 5
        status = StageStatus.OK if cf is web else StageStatus.PARTIAL
        result = _manifest(cf, rows=rows, status=status, table="web_logs", parquet_path=path)
        return SimpleNamespace(staged_file=result, prepared=object(), parquet_path=str(path),
                               rows_written=rows, fallback_reason=None)

    flatten_calls = []

    def flatten(received_case, table, paths, batch_id, ingested_at, **kwargs):
        assert received_case == case_dir
        assert table == "linux_logs"
        assert paths == normal_paths
        assert batch_id == direct_batch_ids[0]
        assert ingested_at is direct_times[0]
        assert kwargs["options"] is options
        flatten_calls.append((table, paths))
        return 2

    cleanup_calls = []

    def cleanup(result):
        assert result.output_format == "staged"
        cleanup_calls.append(result.source_path)
        remove_staged(result)

    monkeypatch.setattr(orchestrator, "stage_aux_file", stage)
    monkeypatch.setattr(orchestrator, "get_job_queue", get_queue)
    monkeypatch.setattr(orchestrator, "flatten_table", flatten)
    monkeypatch.setattr(orchestrator, "remove_staged", cleanup)
    _install_direct(monkeypatch, direct)
    report = orchestrator.run_aux_ingest(
        case_dir, [], workers=6, keep_staging=False, classified=classified,
        cluster_config=ClusterConfig.local(), progress=progress, options=options,
    )

    assert events == ["queue-start", "queue-closed", f"direct:{KIND_WEB_ACCESS}", f"direct:{KIND_IIS}"]
    assert len(flatten_calls) == 1
    assert direct_times[0] is direct_times[1]
    assert report.rows_written == {"web_logs": 8, "linux_logs": 2}
    assert report.files_ok == 2
    assert report.files_partial == 1
    assert report.files_unknown == 1
    assert report.files_discovered == 4
    assert len(progress.results) == 4
    assert len({result.source_path for result in progress.results}) == 4
    assert progress.rows == [("web_logs", 3), ("web_logs", 5), ("linux_logs", 2)]
    assert sorted(cleanup_calls) == sorted([str(unknown.path), str(syslog.path)])
    assert all(path.exists() for path in published_paths)
    assert not Path(normal_paths[0]).exists()


@pytest.mark.parametrize("reason", ["native component unavailable", "encoding is utf-16", "unsupported syntax"])
def test_direct_compatibility_replay_reuses_preparation_and_disables_native(tmp_path, monkeypatch, reason):
    cf = ClassifiedFile(tmp_path / "nginx.log", "HOST", 128, KIND_WEB_ACCESS)
    options = IngestOptions(parser_backend="auto", memory_limit="4GB", threads=4, staging_format="arrow", direct_parquet=True)
    prepared = object()
    calls = []
    progress = Progress()

    def direct(*args, **kwargs):
        return SimpleNamespace(staged_file=None, prepared=prepared, parquet_path=None,
                               rows_written=0, fallback_reason=reason)

    def stage(received_cf, staging_dir, replay_options, *, prepared):
        assert received_cf is cf
        assert prepared is expected_prepared
        assert replay_options.parser_backend == "python"
        assert replay_options.direct_parquet is False
        assert replay_options.memory_limit == options.memory_limit
        assert replay_options.threads == options.threads
        assert replay_options.staging_format == options.staging_format
        assert replay_options.staging_chunk_bytes == options.staging_chunk_bytes
        assert replay_options.flatten_batch_bytes == options.flatten_batch_bytes
        calls.append("replay")
        path = staging_dir / "replayed.arrow"
        path.write_bytes(b"staging fixture")
        result = _manifest(cf, rows=2, table="web_logs", staged_path=path)
        result.backend_reason = "must be replaced with the direct fallback reason"
        return result

    def flatten(*args, **kwargs):
        calls.append("flatten")
        assert len(args[2]) == 1
        return 2

    expected_prepared = prepared
    _install_direct(monkeypatch, direct)
    monkeypatch.setattr(orchestrator, "stage_aux_file", stage)
    monkeypatch.setattr(orchestrator, "get_job_queue", _forbidden)
    monkeypatch.setattr(orchestrator, "flatten_table", flatten)
    report = orchestrator.run_aux_ingest(
        tmp_path / "case", [], keep_staging=False, classified=[cf], options=options,
        cluster_config=ClusterConfig.local(), progress=progress,
    )
    assert calls == ["replay", "flatten"]
    assert report.rows_written == {"web_logs": 2}
    assert report.staged_files[0].backend_reason == reason
    assert report.staged_files[0].parser_backend == "python"
    assert len(progress.results) == 1
    assert progress.rows == [("web_logs", 2)]
    assert not Path(report.staged_files[0].ndjson_path).exists()


@pytest.mark.parametrize(("keep_staging", "config", "message"), [
    (True, ClusterConfig.local(), "keep_staging=False"),
    (False, ClusterConfig(broker_url="redis://invalid"), "local execution and local storage"),
    (False, ClusterConfig(storage_backend="s3", s3_bucket="fixture"), "local execution and local storage"),
])
def test_direct_invalid_execution_is_rejected_before_discovery(tmp_path, monkeypatch, keep_staging, config, message):
    monkeypatch.setattr(orchestrator, "discover_and_classify", _forbidden)
    monkeypatch.setattr(orchestrator, "get_job_queue", _forbidden)
    case_dir = tmp_path / "case"
    with pytest.raises(ValueError, match=message):
        orchestrator.run_aux_ingest(
            case_dir, [], keep_staging=keep_staging, cluster_config=config,
            options=IngestOptions(parser_backend="auto", direct_parquet=True),
        )
    assert not case_dir.exists()


def test_zero_valid_direct_source_reports_failed_without_flatten_or_cleanup(tmp_path, monkeypatch):
    cf = ClassifiedFile(tmp_path / "iis.log", "HOST", 1, KIND_IIS)
    result = _manifest(cf, status=StageStatus.FAILED, table="web_logs")
    result.output_format = "parquet"
    result.parser_backend = "native"

    def direct(*args, **kwargs):
        return SimpleNamespace(staged_file=result, prepared=object(), parquet_path=None,
                               rows_written=0, fallback_reason=None)

    _install_direct(monkeypatch, direct)
    monkeypatch.setattr(orchestrator, "get_job_queue", _forbidden)
    monkeypatch.setattr(orchestrator, "stage_aux_file", _forbidden)
    monkeypatch.setattr(orchestrator, "flatten_table", _forbidden)
    monkeypatch.setattr(orchestrator, "remove_staged", _forbidden)
    progress = Progress()
    report = orchestrator.run_aux_ingest(
        tmp_path / "case", [], keep_staging=False, classified=[cf],
        cluster_config=ClusterConfig.local(), progress=progress,
        options=IngestOptions(parser_backend="auto", direct_parquet=True),
    )
    assert report.files_failed == 1
    assert report.rows_written == {}
    assert report.staged_files == [result]
    assert report.problem_files == [(str(cf.path), StageStatus.FAILED, "fixture parse failure")]
    assert progress.results == [result]
    assert progress.rows == []


def test_direct_fatal_error_does_not_replay_or_continue_to_other_sources(tmp_path, monkeypatch):
    first = ClassifiedFile(tmp_path / "first.log", "HOST", 1, KIND_WEB_ACCESS)
    second = ClassifiedFile(tmp_path / "second.log", "HOST", 1, KIND_IIS)
    failure = OSError("direct persistence failed")
    calls = []

    def direct(cf, *args, **kwargs):
        calls.append(cf)
        raise failure

    _install_direct(monkeypatch, direct)
    monkeypatch.setattr(orchestrator, "stage_aux_file", _forbidden)
    monkeypatch.setattr(orchestrator, "get_job_queue", _forbidden)
    monkeypatch.setattr(orchestrator, "flatten_table", _forbidden)
    with pytest.raises(OSError) as caught:
        orchestrator.run_aux_ingest(
            tmp_path / "case", [], keep_staging=False, classified=[first, second],
            cluster_config=ClusterConfig.local(), options=IngestOptions(parser_backend="auto", direct_parquet=True),
        )
    assert caught.value is failure
    assert calls == [first]


def test_direct_fallback_without_preparation_is_fatal_instead_of_repreparing(tmp_path, monkeypatch):
    cf = ClassifiedFile(tmp_path / "access.log", "HOST", 1, KIND_WEB_ACCESS)

    def direct(*args, **kwargs):
        return SimpleNamespace(staged_file=None, prepared=None, parquet_path=None,
                               rows_written=0, fallback_reason="invalid helper result")

    _install_direct(monkeypatch, direct)
    monkeypatch.setattr(orchestrator, "stage_aux_file", _forbidden)
    monkeypatch.setattr(orchestrator, "get_job_queue", _forbidden)
    monkeypatch.setattr(orchestrator, "flatten_table", _forbidden)
    with pytest.raises(NativeBatchError, match="lacks prepared source identity"):
        orchestrator.run_aux_ingest(
            tmp_path / "case", [], keep_staging=False, classified=[cf],
            cluster_config=ClusterConfig.local(), options=IngestOptions(parser_backend="auto", direct_parquet=True),
        )


def test_direct_disabled_keeps_web_source_in_ordinary_queue(tmp_path, monkeypatch):
    cf = ClassifiedFile(tmp_path / "access.log", "HOST", 1, KIND_WEB_ACCESS)
    result = _manifest(cf)
    calls = []
    options = IngestOptions(direct_parquet=False)
    _install_direct(monkeypatch, _forbidden)

    class Queue:
        def submit_all(self, fn, args_list, on_result=None):
            assert args_list[0][0] is cf
            assert args_list[0][2] is options
            calls.append("queued")
            return [result]

    monkeypatch.setattr(orchestrator, "get_job_queue", lambda *args, **kwargs: Queue())
    monkeypatch.setattr(orchestrator, "flatten_table", _forbidden)
    report = orchestrator.run_aux_ingest(
        tmp_path / "case", [], classified=[cf], options=options,
        cluster_config=ClusterConfig.local(),
    )
    assert calls == ["queued"]
    assert report.staged_files == [result]
