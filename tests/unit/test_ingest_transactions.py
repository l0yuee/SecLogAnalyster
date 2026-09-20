from __future__ import annotations

import json
from pathlib import Path

import pytest

from seclogx import Case
from seclogx.ingest.resources import IngestOptions
from seclogx.ingest.transactions import cleanup_uncommitted


def source_tree(tmp_path, web=False):
    root = tmp_path / 'input'
    root.mkdir()
    for i in range(3):
        line = (f'192.0.2.{i+1} - - [20/Sep/2026:00:00:00 +0000] "GET /{i} HTTP/1.1" 200 10\n'
                if web else f'<34>1 2026-09-20T00:00:00Z host app 1 - - source {i}\n')
        (root / f'{i}.log').write_text(line * 10, encoding='utf-8')
    return root


@pytest.mark.parametrize('web', [False, True])
def test_failed_batch_is_invisible_and_retry_does_not_duplicate(tmp_path, monkeypatch, web):
    import seclogx.ingest.logsources.orchestrator as orchestrator
    import seclogx.ingest.logsources.direct as direct

    root = source_tree(tmp_path, web)
    case = Case.create('atomic', case_root=tmp_path / 'cases')
    options = IngestOptions(flatten_batch_bytes=1)
    owner, name = (direct, 'direct_web_file') if web else (orchestrator, 'flatten_table')
    original = getattr(owner, name)
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('injected conversion failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, name, fail_second)
    with pytest.raises(OSError, match='injected conversion'):
        case.ingest([str(root)], workers=1, options=options)
    assert case.db.tables == []
    assert case.info()['ingest_runs'] == []
    assert list((case.case_dir / '.ingest').rglob('*.parquet'))
    monkeypatch.setattr(owner, name, original)
    report = case.ingest([str(root)], workers=1, options=options)
    table = 'web_logs' if web else 'syslog'
    assert case.query(f'SELECT count(*) n FROM {table}').iloc[0, 0] == 30
    assert report.aux.rows_written[table] == 30
    assert len(case.info()['ingest_runs']) == 1
    states = [json.loads(p.read_text()) for p in (case.case_dir / '.ingest').glob('*/state.json')]
    assert {s['phase'] for s in states} == {'cleaned', 'committed'}


def test_unchanged_sources_are_skipped_but_same_content_other_host_is_preserved(tmp_path):
    root = source_tree(tmp_path)
    case = Case.create('repeat', case_root=tmp_path / 'cases')
    case.ingest([f'{root}:A'], workers=1)
    repeat = case.ingest([f'{root}:A'], workers=1)
    assert len(repeat.already_imported) == 3
    assert repeat.aux.rows_written == {}
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 30
    case.ingest([f'{root}:B'], workers=1)
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 60
    assert set(case.query('SELECT DISTINCT host FROM syslog')['host']) == {'A', 'B'}


def test_source_modified_without_size_change_is_not_skipped(tmp_path):
    root = source_tree(tmp_path)
    path = root / '0.log'
    case = Case.create('changed', case_root=tmp_path / 'cases')
    case.ingest([str(path)], workers=1)
    path.write_text(path.read_text().replace('source 0', 'source 9'))
    report = case.ingest([str(path)], workers=1)
    assert report.already_imported == []
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 20


def test_metadata_commit_failure_hides_output(tmp_path, monkeypatch):
    import seclogx.ingest.transactions as transactions

    root = source_tree(tmp_path)
    case = Case.create('diskfull', case_root=tmp_path / 'cases')
    real_write = transactions.atomic_json

    def fail_case(path, value):
        if Path(path) == case.case_dir.resolve() / 'case.json':
            raise OSError('metadata disk full')
        real_write(path, value)

    monkeypatch.setattr(transactions, 'atomic_json', fail_case)
    with pytest.raises(OSError, match='disk full'):
        case.ingest([str(root)], workers=1)
    assert Case.open('diskfull', case_root=tmp_path / 'cases').db.tables == []
    assert case.info()['ingest_runs'] == []
    monkeypatch.setattr(transactions, 'atomic_json', real_write)
    case.ingest([str(root)], workers=1)
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 30


def test_open_query_keeps_committed_snapshot(tmp_path):
    root = source_tree(tmp_path)
    case = Case.create('snapshot', case_root=tmp_path / 'cases')
    case.ingest([str(root / '0.log')], workers=1)
    reader = Case.open('snapshot', case_root=tmp_path / 'cases')
    assert reader.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 10
    case.ingest([str(root / '1.log')], workers=1)
    assert reader.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 10
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 20
    assert cleanup_uncommitted(case.case_dir, case.cluster_config) == []


def test_existing_lake_is_adopted_without_rewriting(synth_case, tmp_path):
    original = list((synth_case.case_dir / 'lake').rglob('*.parquet'))
    original_bytes = {p: p.read_bytes() for p in original}
    root = source_tree(tmp_path)
    synth_case.ingest([str(root)], workers=1)
    assert synth_case.query('SELECT count(*) n FROM events').iloc[0, 0] == 2
    assert synth_case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 30
    assert all(p.read_bytes() == data for p, data in original_bytes.items())


def test_legacy_provenance_is_indexed_before_retry(tmp_path):
    from seclogx.ingest.common import SourceSpec
    from seclogx.ingest.logsources.orchestrator import run_aux_ingest

    root = source_tree(tmp_path)
    case = Case.create('legacy', case_root=tmp_path / 'cases')
    run_aux_ingest(case.case_dir, [SourceSpec(root, 'OLD')], workers=1)
    report = case.ingest([f'{root}:OLD'], workers=1)
    assert len(report.already_imported) == 3
    assert {item['status'] for item in report.already_imported} == {'legacy_unknown'}
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 30


def test_cleanup_preserves_live_worker_output_then_removes_after_exit(tmp_path):
    import subprocess
    import sys
    import time
    from seclogx.ingest.job_control import process_identity
    from seclogx.ingest.persistence import atomic_json
    from seclogx.ingest.transactions import IngestTransaction
    from seclogx.ingest.scan import scan_sources
    from seclogx.ingest.common import SourceSpec

    root = source_tree(tmp_path)
    case = Case.create('orphan', case_root=tmp_path / 'cases')
    tx = IngestTransaction(case.case_dir, case.cluster_config, scan_sources([SourceSpec(root)]))
    with pytest.raises(RuntimeError):
        with tx:
            atomic_json(tx.workspace / 'bulk' / 'data.json', {'owned': True})
            raise RuntimeError('coordinator failed')
    # Model an orphan worker still using the workspace after coordinator exit.
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        atomic_json(tx.workspace / 'workers' / 'child.json', process_identity(process.pid))
        assert cleanup_uncommitted(case.case_dir, case.cluster_config) == []
        assert (tx.workspace / 'bulk' / 'data.json').exists()
    finally:
        process.kill()
        process.wait(timeout=10)
    assert cleanup_uncommitted(case.case_dir, case.cluster_config)
    assert not (tx.workspace / 'bulk').exists()


def test_concurrent_identical_imports_cannot_both_commit(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import seclogx.ingest.transactions as transactions

    root = source_tree(tmp_path)
    case = Case.create('race', case_root=tmp_path / 'cases')
    barrier = threading.Barrier(2, timeout=10)
    original = transactions.IngestTransaction.commit

    def simultaneous(self, report, run):
        barrier.wait()
        return original(self, report, run)

    monkeypatch.setattr(transactions.IngestTransaction, 'commit', simultaneous)
    def ingest():
        return Case.open('race', case_root=tmp_path / 'cases').ingest([str(root)], workers=1)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(ingest), pool.submit(ingest)]
        errors = [future.exception() for future in futures]
    assert sum(error is None for error in errors) == 1
    assert any(isinstance(error, RuntimeError) and 'another ingest' in str(error) for error in errors)
    assert case.query('SELECT count(*) n FROM syslog').iloc[0, 0] == 30


def test_redis_lock_renews_and_detects_lost_ownership(tmp_path, monkeypatch):
    import fakeredis
    import redis
    import time
    from seclogx.distributed.locking import RedisCaseLock

    client = fakeredis.FakeRedis()
    monkeypatch.setattr(redis, 'from_url', lambda *args, **kwargs: client)
    with RedisCaseLock(tmp_path, 'redis://local-test', timeout=0.3) as lock:
        time.sleep(0.7)
        lock.assert_owned()
        client.delete(lock._lock.name)
        with pytest.raises(RuntimeError, match='lost'):
            lock.assert_owned()


def test_streaming_cursor_protects_retired_files_after_parent_close(tmp_path):
    from seclogx.ingest.compaction import compact_case
    from seclogx.ingest.snapshots import cleanup_retired

    root = source_tree(tmp_path)
    case = Case.create('cursor', case_root=tmp_path / 'cases')
    for path in root.glob('*.log'):
        case.ingest([f'{path}:HOST'], workers=1)
    old_files = [Path(p) for p in case.db.parquet_files['syslog']]
    chunks = case.db.sql_chunks('SELECT * FROM syslog', chunksize=1)
    first = next(chunks)
    case.db.close()
    assert compact_case(case.case_dir, case.cluster_config).status == 'committed'
    assert cleanup_retired(case.case_dir, case.cluster_config) == []
    assert all(path.exists() for path in old_files)
    assert len(first) + sum(len(chunk) for chunk in chunks) == 30
    assert set(cleanup_retired(case.case_dir, case.cluster_config)) == {str(p) for p in old_files}


def test_cleanup_rejects_linked_workspace_root(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    from seclogx.ingest.transactions import _validate_removal
    from seclogx.paths import duckdb_path

    root = tmp_path / '.ingest'
    target = root / 'owned' / 'lake' / 'part.parquet'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'preserve')
    original = Path.lstat

    def reparse(path):
        value = original(path)
        if path in (root, Path(duckdb_path(root))):
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return value

    monkeypatch.setattr(Path, 'lstat', reparse)
    with pytest.raises(ValueError, match='reparse point'):
        _validate_removal(root, target)
    assert target.read_bytes() == b'preserve'


def test_catalog_rejects_changed_object_store_identity(tmp_path):
    from types import SimpleNamespace
    from seclogx.distributed.config import ClusterConfig
    from seclogx.ingest.transactions import catalog_files, catalog_storage_identity

    backend = SimpleNamespace(cluster_config=ClusterConfig(storage_backend='s3', s3_bucket='evidence',
                                                          s3_endpoint_url='https://first.example'))
    meta = {'catalog_version': 1, 'catalog': {}, 'catalog_storage': catalog_storage_identity(backend)}
    backend.cluster_config = ClusterConfig(storage_backend='s3', s3_bucket='evidence',
                                          s3_endpoint_url='https://second.example')
    with pytest.raises(ValueError, match='storage configuration differs'):
        catalog_files(tmp_path, backend, meta)
