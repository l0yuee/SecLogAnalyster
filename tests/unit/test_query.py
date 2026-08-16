from __future__ import annotations

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
