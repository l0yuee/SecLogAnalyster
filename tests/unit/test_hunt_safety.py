from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import yaml
from sigma.rule import SigmaRule

from seclogx.detect import hunt, results as results_module
from seclogx.detect.backend import DuckDBBackend
from seclogx.detect.pipeline import seclogx_pipeline
from seclogx.detect.security import restrict_hunt_connection, validate_rule_query
from seclogx.distributed.config import ClusterConfig
from seclogx.query import CaseDB


def _rule(field="cs-method", value="GET", title="Matched requests"):
    return {"title": title, "id": str(uuid4()), "status": "test", "level": "high",
            "logsource": {"category": "webserver"},
            "detection": {"selection": {field: value}, "condition": "selection"}}


def _write_rules(directory: Path, rules: list[dict]) -> Path:
    directory.mkdir()
    for index, rule in enumerate(rules):
        (directory / f"{index}.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    return directory


def _case(directory: Path, rows: int = 10, **extra) -> Path:
    table_dir = directory / "lake" / "web_logs"
    table_dir.mkdir(parents=True)
    pq.write_table(pa.table({"method": ["GET"] * rows, "request_id": list(range(rows)), **extra}),
                   table_dir / "part.parquet")
    return directory


@pytest.mark.parametrize("field", [
    "method; SELECT 1 --", "method) OR true --", "(event_data ->> 'Image')",
    'method"', "read_text('untrusted')", "a.b", "method\nFROM read_text('untrusted') --",
])
def test_untrusted_fields_cannot_impersonate_sql(field):
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
    with pytest.raises(Exception, match="unsupported Sigma field name"):
        backend.convert_rule(SigmaRule.from_dict(_rule(field)))


def test_mapping_owned_by_backend_and_unknown_safe_identifier_is_quoted():
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
    assert backend.escape_and_quote_field("Image") == "(event_data ->> 'Image')"
    assert backend.escape_and_quote_field("cs-method") == '"method"'
    assert backend.escape_and_quote_field("unknown_column") == '"unknown_column"'


@pytest.mark.parametrize("modifier", ["", "|contains", "|startswith", "|endswith", "|re"])
def test_rule_values_remain_data_even_with_sql_punctuation(tmp_path, modifier):
    marker = tmp_path / "unexpected.csv"
    value = f"x'; COPY (SELECT 1) TO '{marker.as_posix()}'; --"
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
    fragments = backend.convert_rule(SigmaRule.from_dict(_rule("cs-method" + modifier, value)))
    with duckdb.connect() as con:
        query = 'SELECT * FROM web_logs WHERE ' + fragments[0]
        validate_rule_query(con, query, "web_logs")
        con.execute("CREATE TABLE web_logs(method VARCHAR)")
        con.execute("INSERT INTO web_logs VALUES (?)", [value])
        # Regex content may be invalid RE2 syntax, but it remains a literal.
        try:
            con.execute(query).fetchall()
        except duckdb.InvalidInputException:
            assert modifier == "|re"
    assert not marker.exists()


def test_regular_expression_preserves_backslash_semantics(tmp_path):
    case = _case(tmp_path / "case", method_text=["cmd.exe", "acmd.exe", "cmdXexe"] + ["other"] * 7)
    rules = _write_rules(tmp_path / "rules", [_rule("method_text|re", r"\bcmd\.exe\b")])
    result = hunt.run_hunt(case, rules)
    assert not result.failures
    assert result.total_matches == 1
    assert result.matches["method_text"].tolist() == ["cmd.exe"]


@pytest.mark.parametrize("query", [
    "SELECT * FROM web_logs WHERE true; SELECT 2",
    "COPY (SELECT 1) TO 'unused.csv'",
    "SELECT * FROM web_logs WHERE true UNION ALL SELECT * FROM web_logs",
    "SELECT * FROM web_logs WHERE method = (SELECT 'GET')",
    "SELECT * FROM web_logs WHERE getenv('PATH') = 'x'",
    "SELECT * FROM read_text('unused') WHERE true",
    "SELECT * FROM web_logs WHERE true ORDER BY method",
    "SELECT * REPLACE ('changed' AS method) FROM web_logs WHERE true",
])
def test_query_boundary_rejects_non_predicate_sql(query):
    with duckdb.connect() as con:
        with pytest.raises(ValueError):
            validate_rule_query(con, query, "web_logs")


def test_execution_connection_cannot_access_other_files_or_unlock(tmp_path):
    case = _case(tmp_path / "case")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("not a case input", encoding="utf-8")
    marker = tmp_path / "unexpected.csv"
    with CaseDB(case) as db:
        restrict_hunt_connection(db, case / "hunts" / "test")
        assert db.connection.execute("SELECT count(*) FROM web_logs").fetchone()[0] == 10
        for query, params in [
            ("SELECT * FROM read_text(?)", [str(unrelated)]),
            (f"COPY (SELECT 1) TO '{marker.as_posix()}'", []),
            ("SET enable_external_access = true", []),
            ("SET lock_configuration = false", []),
        ]:
            with pytest.raises(duckdb.Error):
                db.connection.execute(query, params)
    assert not marker.exists()


def test_injected_field_is_reported_and_safe_rules_still_run(tmp_path):
    case = _case(tmp_path / "case")
    marker = tmp_path / "unexpected.csv"
    field = f"method = 'GET'; COPY (SELECT 1) TO '{marker.as_posix()}'; --"
    rules = _write_rules(tmp_path / "rules", [_rule(field), _rule()])
    result = hunt.run_hunt(case, rules)
    assert len(result.failures) == 1
    assert "unsupported Sigma field name" in result.failures[0].reason
    assert result.total_matches == 10
    assert not marker.exists()


def test_all_results_spill_and_export_with_exact_counts_across_rules(tmp_path, monkeypatch):
    case = _case(tmp_path / "case", 11)
    rules = _write_rules(tmp_path / "rules", [_rule(title="First"), _rule(title="Second")])
    monkeypatch.setattr(results_module, "_EAGER_ROWS", 15)
    # The implementation must not use CaseDB.sql/fetchdf even for a wide rule.
    monkeypatch.setattr(CaseDB, "sql", lambda *args: pytest.fail("eager query was used"))
    result = hunt.run_hunt(case, rules)
    assert not result.failures
    assert result.is_spilled and result.total_matches == 22
    with pytest.raises(MemoryError, match="22 complete matches"):
        result.to_dataframe()
    preview = result.preview(3)
    assert len(preview) == 3
    assert preview.attrs["complete"] is False
    assert preview.attrs["total_matches"] == 22
    chunks = list(result.iter_chunks(4))
    assert sum(map(len, chunks)) == 22 and max(map(len, chunks)) <= 4
    assert set(pd.concat(chunks)["request_id"]) == set(range(11))
    exported = tmp_path / "matches.csv"
    result.save(exported)
    assert len(pd.read_csv(exported)) == 22
    index = json.loads((result.result_dir / "results.json").read_text(encoding="utf-8"))
    assert index["total_matches"] == 22
    assert len(index["files"]) == 2
    assert all((result.result_dir / name).is_file() for name in index["files"])


def test_aggregate_byte_budget_and_preview_byte_budget(tmp_path, monkeypatch):
    case = _case(tmp_path / "case", 3, payload=["A" * 1000] * 3)
    rules = _write_rules(tmp_path / "rules", [_rule(), _rule()])
    monkeypatch.setattr(results_module, "_EAGER_BYTES", 5000)
    monkeypatch.setattr(results_module, "_PREVIEW_BYTES", 1800)
    result = hunt.run_hunt(case, rules)
    assert result.is_spilled and result.total_matches == 6
    preview = result.preview(6)
    assert len(preview) <= 1
    assert int(preview.memory_usage(index=True, deep=True).sum()) <= 1800


def test_failed_rule_does_not_publish_partial_matches(tmp_path, monkeypatch):
    case = _case(tmp_path / "case")
    rules = _write_rules(tmp_path / "rules", [_rule("column_missing")])
    result = hunt.run_hunt(case, rules)
    assert len(result.failures) == 1
    assert result.total_matches == 0 and not result.files
    assert not list(result.result_dir.rglob("*.partial"))


def test_distributed_workers_return_only_artifact_paths(tmp_path, monkeypatch):
    from seclogx.ingest import snapshots
    from seclogx.distributed.locking import LocalCaseLock

    monkeypatch.setattr(snapshots, "get_case_lock", lambda case, config: LocalCaseLock(case))
    case = _case(tmp_path / "case", 7)
    rules = _write_rules(tmp_path / "rules", [_rule(), _rule()])
    monkeypatch.setattr(results_module, "_EAGER_ROWS", 10)

    class InlineQueue:
        def submit_all(self, function, arguments):
            outputs = [function(*args) for args in arguments]
            assert all(isinstance(path, str) for output in outputs for path in output[0])
            return outputs

    monkeypatch.setattr(hunt, "get_job_queue", lambda *args, **kwargs: InlineQueue())
    result = hunt.run_hunt(case, rules, cluster_config=ClusterConfig(broker_url="redis://test"))
    assert not result.failures
    assert result.is_spilled and result.total_matches == 14
    assert sum(len(chunk) for chunk in result.iter_chunks()) == 14


def test_results_reopen_without_rerunning_hunt(tmp_path, monkeypatch):
    case = _case(tmp_path / "case", 9)
    rules = _write_rules(tmp_path / "rules", [_rule()])
    monkeypatch.setattr(results_module, "_EAGER_ROWS", 5)
    original = hunt.run_hunt(case, rules)
    reopened = results_module.HuntResults.open(original.result_dir)
    assert reopened.is_spilled and reopened.total_matches == 9
    assert reopened.preview(2)["request_id"].tolist() == original.preview(2)["request_id"].tolist()
    exported = tmp_path / "reopened.csv"
    reopened.save(exported)
    assert len(pd.read_csv(exported)) == 9


def test_result_reopen_rejects_path_escape_and_missing_rows(tmp_path):
    case = _case(tmp_path / "case", 9)
    rules = _write_rules(tmp_path / "rules", [_rule()])
    original = hunt.run_hunt(case, rules)
    index = original.result_dir / "results.json"
    manifest = json.loads(index.read_text(encoding="utf-8"))
    changed = {**manifest, "files": ["../unexpected.parquet"]}
    index.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid file path"):
        results_module.HuntResults.open(original.result_dir)
    changed = {**manifest, "total_matches": 10}
    index.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="recorded match count"):
        results_module.HuntResults.open(original.result_dir)


def test_export_failure_preserves_existing_destination(tmp_path):
    case = _case(tmp_path / "case")
    rules = _write_rules(tmp_path / "rules", [_rule()])
    result = hunt.run_hunt(case, rules)
    target = tmp_path / "previous.csv"
    target.write_text("previous results", encoding="utf-8")
    Path(result.files[0]).unlink()
    with pytest.raises(duckdb.Error):
        result.save(target)
    assert target.read_text(encoding="utf-8") == "previous results"
    assert not list(tmp_path.glob(".previous.csv.*.tmp"))


def test_variable_width_chunks_are_bounded_before_pandas(tmp_path, monkeypatch):
    case = _case(tmp_path / "case", 10, payload=["a", "b", "x" * 2000] * 3 + ["end"])
    rules = _write_rules(tmp_path / "rules", [_rule()])
    monkeypatch.setattr(results_module, "_READ_BATCH_BYTES", 1000)
    result = hunt.run_hunt(case, rules)
    chunks = list(result.iter_chunks(10))
    assert sum(map(len, chunks)) == 10
    for chunk in chunks:
        if any(len(value) > 1000 for value in chunk["payload"]):
            assert len(chunk) == 1  # an indivisible wide row gets its own chunk


@pytest.mark.parametrize("field,value,condition", [
    ("flag", True, "selection"), ("flag", False, "selection"),
    ("cs-method", None, "selection"), ("cs-method|exists", True, "selection"),
    ("cs-method", ["GET", "POST"], "selection"),
    ("cs-method", "POST", "not selection"),
])
def test_supported_predicate_types_pass_security_boundary(tmp_path, field, value, condition):
    case = _case(tmp_path / "case", 3, flag=[True, False, True])
    rule = _rule(field, value)
    rule["detection"]["condition"] = condition
    rules = _write_rules(tmp_path / "rules", [rule])
    result = hunt.run_hunt(case, rules)
    assert not result.failures


def test_ordinary_reads_use_arrow_batches_not_python_per_record(tmp_path, monkeypatch):
    case = _case(tmp_path / "case", 1000)
    rules = _write_rules(tmp_path / "rules", [_rule()])
    result = hunt.run_hunt(case, rules)
    original = pq.ParquetFile.iter_batches
    requested = []

    def observed(parquet, *args, **kwargs):
        requested.append(kwargs["batch_size"])
        yield from original(parquet, *args, **kwargs)

    monkeypatch.setattr(pq.ParquetFile, "iter_batches", observed)
    assert sum(len(chunk) for chunk in result.iter_chunks()) == 1000
    assert requested and all(size > 1 for size in requested)
