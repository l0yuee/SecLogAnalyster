from __future__ import annotations

import pandas as pd

from seclogx.case import Case
from seclogx.query import CaseDB


def test_summary(synth_case: Case):
    df = synth_case.summary()
    assert len(df) == 1  # one (host, channel, event_id) group
    assert df.iloc[0]["count"] == 2


def test_hosts_and_channels(synth_case: Case):
    assert synth_case.hosts() == ["TESTHOST"]
    assert synth_case.channels() == ["Microsoft-Windows-Sysmon/Operational"]


def test_search_full_text(synth_case: Case):
    df = synth_case.db.search("mimikatz")
    assert len(df) == 1
    assert df.iloc[0]["record_id"] == 1


def test_by_event_id(synth_case: Case):
    df = synth_case.db.by_event_id(1)
    assert len(df) == 2
    df_missing = synth_case.db.by_event_id(9999)
    assert df_missing.empty


def test_by_host(synth_case: Case):
    assert len(synth_case.db.by_host("TESTHOST")) == 2
    assert synth_case.db.by_host("NOPE").empty


def test_empty_case_raises_clear_error(tmp_path):
    case = Case.create("empty", case_root=tmp_path / "cases")
    db = CaseDB(case.case_dir)
    try:
        db.sql("SELECT 1")
        assert False, "expected RuntimeError for a case with no ingested data"
    except RuntimeError as e:
        assert "no ingested data" in str(e)


def test_sql_chunks_matches_eager_and_splits_into_multiple_chunks(synth_case: Case):
    # Register an ad hoc large table directly on the CaseDB's connection --
    # exercises DuckDB's actual chunked-fetch mechanism (not just a
    # trivially small 2-row case), independent of any particular log family.
    db = synth_case.db
    db.connection.execute("CREATE TABLE big AS SELECT range AS i FROM range(50000)")

    chunks = list(db.sql_chunks("SELECT * FROM big ORDER BY i", chunksize=2048))
    assert len(chunks) > 1, "50000 rows at a 2048-row chunksize should yield more than one chunk"
    assert all(len(c) <= 2048 + 1 for c in chunks)  # roughly bounded, not proportional to total size

    combined = pd.concat(chunks, ignore_index=True)
    eager = db.sql("SELECT * FROM big ORDER BY i")
    pd.testing.assert_frame_equal(combined, eager)


def test_sql_chunks_empty_result_yields_no_chunks(synth_case: Case):
    chunks = list(synth_case.db.sql_chunks("SELECT * FROM events WHERE event_id = 999999"))
    assert chunks == []


def test_sql_chunks_requires_data(tmp_path):
    case = Case.create("emptychunks", case_root=tmp_path / "cases")
    db = CaseDB(case.case_dir)
    try:
        list(db.sql_chunks("SELECT 1"))
        assert False, "expected RuntimeError for a case with no ingested data"
    except RuntimeError as e:
        assert "no ingested data" in str(e)


def test_table_chunks_matches_table(synth_case: Case):
    chunks = list(synth_case.db.table_chunks("events", order_by="record_id"))
    combined = pd.concat(chunks, ignore_index=True)
    pd.testing.assert_frame_equal(combined, synth_case.db.table("events", order_by="record_id"))


def test_table_chunks_missing_table_yields_no_chunks(synth_case: Case):
    assert list(synth_case.db.table_chunks("does_not_exist")) == []


def test_case_query_chunks(synth_case: Case):
    chunks = list(synth_case.query_chunks("SELECT * FROM events ORDER BY record_id"))
    combined = pd.concat(chunks, ignore_index=True)
    pd.testing.assert_frame_equal(combined, synth_case.query("SELECT * FROM events ORDER BY record_id"))
