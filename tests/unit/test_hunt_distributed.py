from __future__ import annotations

import pytest

from seclogx.case import Case
from seclogx.detect import hunt as hunt_module
from seclogx.distributed.config import ClusterConfig
from seclogx.distributed.queue import JobQueue


class _InlineJobQueue(JobQueue):
    """Runs every task synchronously in-process, in submission order --
    exercises `_run_hunt_distributed`'s fan-out/merge logic without
    needing a real broker. Distinct from LocalJobQueue: that one still
    uses a ProcessPoolExecutor (real subprocesses, needs picklable rule
    filters -- which chunk args already are, but this keeps the test
    fast and avoids multiprocessing entirely)."""

    def submit_all(self, fn, args_list):
        return [fn(*args) for args in args_list]


def test_distributed_hunt_matches_sequential_hunt(synth_case: Case, monkeypatch):
    sequential = synth_case.hunt()

    monkeypatch.setattr(hunt_module, "get_job_queue", lambda *a, **k: _InlineJobQueue())
    distributed_config = ClusterConfig(broker_url="redis://fake-for-this-test")
    distributed = hunt_module.run_hunt(synth_case.case_dir, cluster_config=distributed_config)

    assert not distributed.failures
    assert distributed.rule_summary["matches"].sum() == sequential.rule_summary["matches"].sum()
    assert set(distributed.rule_summary["rule_id"]) == set(sequential.rule_summary["rule_id"])
    assert len(distributed.matches) == len(sequential.matches)
    if not sequential.matches.empty:
        assert set(distributed.matches["sigma_rule_id"]) == set(sequential.matches["sigma_rule_id"])


def test_chunk_rules_splits_evenly_and_covers_every_rule():
    rules = list(range(10))
    chunks = hunt_module._chunk_rules(rules, 4)
    assert sum(len(c) for c in chunks) == 10
    assert sorted(x for c in chunks for x in c) == rules
    assert len(chunks) <= 4


def test_chunk_rules_handles_empty_and_oversized_chunk_count():
    assert hunt_module._chunk_rules([], 4) == []
    chunks = hunt_module._chunk_rules([1, 2], 10)
    assert sorted(x for c in chunks for x in c) == [1, 2]
    assert len(chunks) <= 2


def test_run_hunt_sequential_path_unaffected_when_not_distributed(synth_case: Case):
    # cluster_config explicitly local (no broker) -- must take the exact
    # same code path as before this feature existed, not the fan-out one.
    results = hunt_module.run_hunt(synth_case.case_dir, cluster_config=ClusterConfig.local())
    assert not results.failures
    assert results.rule_summary["matches"].sum() == 1
