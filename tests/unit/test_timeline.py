from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from seclogx.case import Case
from seclogx.ingest.evtx.flatten import flatten_case
from seclogx.ingest.evtx.manifest import StagedFile, now_iso
from seclogx.timeline import build_timeline, build_timeline_chunks


def _record(record_id: int, event_id: int, channel: str, time: str) -> dict:
    return {
        "event_record_id": record_id,
        "timestamp": f"{time} UTC",
        "data": json.dumps(
            {
                "Event": {
                    "System": {
                        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                        "EventID": event_id,
                        "Version": 5,
                        "Level": 4,
                        "Task": 1,
                        "Opcode": 0,
                        "Keywords": "0x8000000000000000",
                        "TimeCreated": {"#attributes": {"SystemTime": time}},
                        "EventRecordID": record_id,
                        "Correlation": None,
                        "Execution": {"#attributes": {"ProcessID": 100, "ThreadID": 101}},
                        "Channel": channel,
                        "Computer": "TESTHOST",
                        "Security": {"#attributes": {"UserID": "S-1-5-18"}},
                    },
                    "EventData": {},
                }
            }
        ),
    }


@pytest.fixture
def timeline_case(tmp_path: Path) -> Case:
    """Three records spread across two channels/event IDs with distinct,
    ordered timestamps -- specifically for exercising time-window and
    event-id-list filtering that the shared synth_case fixture (identical
    timestamps on both its records) can't exercise."""
    case = Case.create("timeline_synth", case_root=tmp_path / "cases")

    records = [
        _record(1, 1, "Microsoft-Windows-Sysmon/Operational", "2026-01-14T02:00:00.000000Z"),
        _record(2, 3, "Microsoft-Windows-Sysmon/Operational", "2026-01-14T02:10:00.000000Z"),
        _record(3, 4624, "Security", "2026-01-14T02:20:00.000000Z"),
    ]
    ndjson_path = tmp_path / "fake.ndjson"
    with ndjson_path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    staged = StagedFile(
        source_path="/synthetic/fake.evtx",
        source_file="fake.evtx",
        host="TESTHOST",
        file_sha256="0" * 64,
        size_bytes=10,
        status="ok",
        record_count=len(records),
        error_count=0,
        error_message=None,
        ndjson_path=str(ndjson_path),
        staged_at=now_iso(),
    )
    flatten_case(case.case_dir, [staged], "timelinebatch")
    return case


def test_build_timeline_unfiltered_returns_all_rows_ordered(timeline_case: Case):
    df = build_timeline(timeline_case.db)
    assert len(df) == 3
    assert list(df["event_id"]) == [1, 3, 4624]  # ordered by time_created


def test_build_timeline_filters_by_time_window(timeline_case: Case):
    df = build_timeline(timeline_case.db, start="2026-01-14T02:05:00", end="2026-01-14T02:15:00")
    assert list(df["event_id"]) == [3]


def test_build_timeline_filters_by_event_id_single_and_list(timeline_case: Case):
    assert list(build_timeline(timeline_case.db, event_id=3)["event_id"]) == [3]
    assert list(build_timeline(timeline_case.db, event_id=[1, 4624])["event_id"]) == [1, 4624]
    assert build_timeline(timeline_case.db, event_id=999999).empty


def test_build_timeline_filters_by_channel(timeline_case: Case):
    df = build_timeline(timeline_case.db, channel="Security")
    assert list(df["event_id"]) == [4624]


def test_build_timeline_filters_by_host(timeline_case: Case):
    assert len(build_timeline(timeline_case.db, host="TESTHOST")) == 3
    assert build_timeline(timeline_case.db, host="NOPE").empty


def test_build_timeline_combined_filters_are_anded(timeline_case: Case):
    df = build_timeline(timeline_case.db, channel="Microsoft-Windows-Sysmon/Operational", event_id=4624)
    assert df.empty  # event 4624 is on the Security channel, not Sysmon


def test_build_timeline_chunks_matches_eager(timeline_case: Case):
    chunks = list(build_timeline_chunks(timeline_case.db, chunksize=1))
    assert len(chunks) >= 1
    combined = pd.concat(chunks, ignore_index=True)
    pd.testing.assert_frame_equal(combined, build_timeline(timeline_case.db))


def test_build_timeline_chunks_filtered_matches_eager(timeline_case: Case):
    chunks = list(build_timeline_chunks(timeline_case.db, host="TESTHOST", event_id=[1, 3]))
    combined = pd.concat(chunks, ignore_index=True)
    eager = build_timeline(timeline_case.db, host="TESTHOST", event_id=[1, 3])
    pd.testing.assert_frame_equal(combined, eager)
