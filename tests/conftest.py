from __future__ import annotations

import json
from pathlib import Path

import pytest

from seclogx.case import Case
from seclogx.ingest.flatten import flatten_case
from seclogx.ingest.manifest import StagedFile, now_iso


def make_record(
    event_id: int = 1,
    channel: str = "Microsoft-Windows-Sysmon/Operational",
    computer: str = "TESTHOST",
    event_data: dict | None = None,
    record_id: int = 1,
    time: str = "2026-01-01T00:00:00.000000Z",
    process_id: int = 100,
    user_sid: str = "S-1-5-18",
) -> dict:
    """Build a record shaped exactly like `PyEvtxParser.records_json()` output,
    validated empirically against real sample .evtx files (see docs/architecture.md)."""
    return {
        "event_record_id": record_id,
        "timestamp": f"{time} UTC",
        "data": json.dumps(
            {
                "Event": {
                    "System": {
                        "Provider": {
                            "#attributes": {
                                "Name": "Microsoft-Windows-Sysmon",
                                "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
                            }
                        },
                        "EventID": event_id,
                        "Version": 5,
                        "Level": 4,
                        "Task": 1,
                        "Opcode": 0,
                        "Keywords": "0x8000000000000000",
                        "TimeCreated": {"#attributes": {"SystemTime": time}},
                        "EventRecordID": record_id,
                        "Correlation": None,
                        "Execution": {"#attributes": {"ProcessID": process_id, "ThreadID": process_id + 1}},
                        "Channel": channel,
                        "Computer": computer,
                        "Security": {"#attributes": {"UserID": user_sid}},
                    },
                    "EventData": event_data or {},
                }
            }
        ),
    }


@pytest.fixture
def synth_case(tmp_path: Path) -> Case:
    """A case with two synthetic Sysmon process-creation records: one
    mimikatz-like (should match the bundled HackTool rule), one benign."""
    case = Case.create("synth", case_root=tmp_path / "cases")

    records = [
        make_record(
            event_id=1,
            record_id=1,
            event_data={
                "Image": r"C:\Users\evil\Desktop\mimikatz.exe",
                "CommandLine": 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "User": r"TESTHOST\evil",
                "Hashes": "MD5=DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            },
        ),
        make_record(
            event_id=1,
            record_id=2,
            event_data={
                "Image": r"C:\Windows\System32\notepad.exe",
                "CommandLine": "notepad.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "User": r"TESTHOST\alice",
            },
        ),
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
    flatten_case(case.case_dir, [staged], "testbatch")
    return case
