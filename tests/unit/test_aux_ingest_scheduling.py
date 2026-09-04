from pathlib import Path

from seclogx.ingest.common import SourceSpec, StageStatus
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.manifest import AuxStagedFile
from seclogx.ingest.logsources import orchestrator


def test_unknown_files_do_not_enter_worker_queue(tmp_path: Path, monkeypatch):
    unknown = ClassifiedFile(tmp_path / "program", "HOST", 100, None)
    known = ClassifiedFile(tmp_path / "hids.log", "HOST", 200, "qcloud_go")
    monkeypatch.setattr(orchestrator, "discover_and_classify", lambda _sources: [unknown, known])

    staged_locally: list[Path] = []

    def fake_stage(cf, _staging_dir):
        staged_locally.append(cf.path)
        status = StageStatus.UNKNOWN if cf.kind is None else StageStatus.OK
        return AuxStagedFile(
            source_path=str(cf.path),
            source_file=cf.path.name,
            host=cf.host,
            file_sha256="",
            size_bytes=cf.size_bytes,
            kind=cf.kind,
            table=None,
            status=status,
            record_count=0,
            error_count=0,
            error_message=None,
        )

    monkeypatch.setattr(orchestrator, "stage_aux_file", fake_stage)

    queued: list[ClassifiedFile] = []

    class FakeQueue:
        def submit_all(self, fn, args_list, on_result=None):
            queued.extend(args[0] for args in args_list)
            results = [fn(*args) for args in args_list]
            if on_result is not None:
                for r in results:
                    on_result(r)
            return results

    monkeypatch.setattr(orchestrator, "get_job_queue", lambda *_args, **_kwargs: FakeQueue())

    report = orchestrator.run_aux_ingest(
        tmp_path / "case", [SourceSpec(tmp_path, "HOST")], workers=2
    )

    assert queued == [known]
    assert staged_locally == [unknown.path, known.path]
    assert report.files_discovered == 2
    assert report.files_ok == 1
    assert report.files_unknown == 1
