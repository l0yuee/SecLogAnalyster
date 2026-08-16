from __future__ import annotations

from seclogx.case import Case


def test_flatten_extracts_expected_fields(synth_case: Case):
    df = synth_case.query("SELECT * FROM events ORDER BY record_id")
    assert len(df) == 2

    row0 = df.iloc[0]
    assert row0["event_id"] == 1
    assert row0["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert row0["host"] == "TESTHOST"
    assert row0["computer"] == "TESTHOST"
    assert row0["process_id"] == 100
    assert row0["user_sid"] == "S-1-5-18"
    assert row0["schema_version"] == 1
    assert str(row0["time_created"]).startswith("2026-01-01")


def test_flatten_event_data_queryable_as_json(synth_case: Case):
    df = synth_case.query("SELECT event_data ->> 'Image' AS image FROM events ORDER BY record_id")
    assert df.iloc[0]["image"] == r"C:\Users\evil\Desktop\mimikatz.exe"
    assert df.iloc[1]["image"] == r"C:\Windows\System32\notepad.exe"


def test_flatten_provenance_columns(synth_case: Case):
    df = synth_case.query("SELECT source_file, file_sha256, ingest_batch_id FROM events LIMIT 1")
    assert df.iloc[0]["source_file"] == "fake.evtx"
    assert df.iloc[0]["file_sha256"] == "0" * 64
    assert df.iloc[0]["ingest_batch_id"] == "testbatch"
