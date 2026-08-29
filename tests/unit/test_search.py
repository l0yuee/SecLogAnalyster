from __future__ import annotations

from pathlib import Path

import pytest

from seclogx.case import Case
from seclogx.errors import ResultTooLargeError, UnknownFieldError
from seclogx.query import ResultSizeEstimate
from seclogx.search import Condition, build_search_sql


# -- Condition --------------------------------------------------------------------


def test_condition_rejects_bad_op():
    with pytest.raises(ValueError):
        Condition(field="x", op="bogus", values=["1"])


def test_condition_rejects_empty_values():
    with pytest.raises(ValueError):
        Condition(field="x", op="equals", values=[])


# -- field resolution + operators, against a real synthetic case ------------------------


def test_search_direct_column_equals(synth_case: Case):
    df = synth_case.search("events", eq={"host": "TESTHOST"})
    assert len(df) == 2

    df = synth_case.search("events", eq={"host": "NOPE"})
    assert df.empty


def test_search_json_key_contains_and_case_sensitivity(synth_case: Case):
    hits = synth_case.search("events", contains={"Image": "mimikatz"})
    assert len(hits) == 1
    assert "mimikatz" in hits.iloc[0]["event_data"].lower()

    # default is case-insensitive
    assert len(synth_case.search("events", contains={"Image": "MIMIKATZ"})) == 1
    # opt into case-sensitive
    assert synth_case.search("events", contains={"Image": "MIMIKATZ"}, case_sensitive=True).empty


def test_search_json_key_regex(synth_case: Case):
    hits = synth_case.search("events", regex={"CommandLine": r"sekurlsa::\w+"})
    assert len(hits) == 1

    hits_ci = synth_case.search("events", regex={"Image": "MIMIKATZ"}, case_sensitive=False)
    assert len(hits_ci) == 1


def test_search_equals_multi_value_is_or(synth_case: Case):
    df = synth_case.search("events", eq={"event_id": ["1", "9999"]})
    assert len(df) == 2  # both synthetic records are event_id 1


def test_search_multiple_conditions_default_and(synth_case: Case):
    both = synth_case.search("events", contains={"Image": "mimikatz"}, eq={"host": "TESTHOST"})
    assert len(both) == 1

    impossible = synth_case.search("events", contains={"Image": "mimikatz"}, eq={"host": "NOPE"})
    assert impossible.empty


def test_search_match_any_is_or(synth_case: Case):
    df = synth_case.search("events", contains={"Image": "mimikatz"}, eq={"host": "NOPE"}, match="any")
    assert len(df) == 1  # the mimikatz condition alone matches


def test_search_unknown_field_on_table_without_json_catchall_raises(synth_case: Case):
    # events has event_data (a JSON object) as a catchall, so an unknown
    # key there is a legitimate "zero matches", not an error (see the
    # no-catchall case below for the actual error path).
    df = synth_case.search("events", eq={"TotallyMadeUpKey": "x"})
    assert df.empty


def test_search_unknown_field_without_any_catchall_raises(tmp_path: Path):
    from seclogx.logsources.ingest import run_aux_ingest
    from seclogx.discovery import SourceSpec

    fixtures = Path(__file__).parent.parent / "fixtures" / "logsources"
    case = Case.create("nocatchall", case_root=tmp_path / "cases")
    run_aux_ingest(case.case_dir, [SourceSpec(path=fixtures, host="LAB01")], workers=1)

    with pytest.raises(UnknownFieldError):
        case.search("scheduled_tasks", eq={"totally_bogus_field": "x"})


def test_search_unknown_table_raises_value_error(synth_case: Case):
    with pytest.raises(ValueError):
        synth_case.search("no_such_table", eq={"a": "1"})


def test_build_search_sql_no_conditions_is_unfiltered(synth_case: Case):
    sql, params = build_search_sql(synth_case.db, "events", [], match="all")
    assert params == []
    df = synth_case.db.sql(sql)
    assert len(df) == 2


# -- chunked / streamed delivery -----------------------------------------------------


def test_search_chunks_matches_eager(synth_case: Case):
    eager = synth_case.search("events", contains={"Image": "exe"})
    chunked_total = sum(len(c) for c in synth_case.search_chunks("events", contains={"Image": "exe"}))
    assert chunked_total == len(eager) == 2


def test_search_to_csv_streams_all_rows(synth_case: Case, tmp_path: Path):
    out = tmp_path / "out.csv"
    n = synth_case.search_to_csv("events", out, contains={"Image": "exe"})
    assert n == 2
    assert len(out.read_text().splitlines()) == 3  # header + 2 rows


def test_search_no_conditions_returns_everything(synth_case: Case):
    df = synth_case.search("events")
    assert len(df) == 2


# -- memory-safety refusal -----------------------------------------------------------


def test_result_size_estimate_fits_in_memory_uses_fallback_when_memory_unknown(monkeypatch):
    monkeypatch.setattr("seclogx.query.available_memory_bytes", lambda: None)
    small = ResultSizeEstimate(row_count=10, estimated_bytes=1000, sampled_rows=10)
    huge = ResultSizeEstimate(row_count=10_000_000, estimated_bytes=50 * 1024 * 1024 * 1024, sampled_rows=2000)
    assert small.fits_in_memory() is True
    assert huge.fits_in_memory() is False


def test_result_size_estimate_fits_in_memory_respects_available_memory(monkeypatch):
    monkeypatch.setattr("seclogx.query.available_memory_bytes", lambda: 1_000_000_000)  # 1GB
    fits = ResultSizeEstimate(row_count=1, estimated_bytes=100_000_000, sampled_rows=1)  # 100MB < 25% of 1GB
    doesnt_fit = ResultSizeEstimate(row_count=1, estimated_bytes=900_000_000, sampled_rows=1)  # 900MB > 25% of 1GB
    assert fits.fits_in_memory() is True
    assert doesnt_fit.fits_in_memory() is False


def test_search_refuses_when_too_large(synth_case: Case, monkeypatch):
    monkeypatch.setattr("seclogx.query.ResultSizeEstimate.fits_in_memory", lambda self, safety_fraction=0.25: False)
    with pytest.raises(ResultTooLargeError):
        synth_case.search("events", contains={"Image": "exe"})

    # the alternatives it points at still work, since they never materialize the whole result
    assert sum(len(c) for c in synth_case.search_chunks("events", contains={"Image": "exe"})) == 2
