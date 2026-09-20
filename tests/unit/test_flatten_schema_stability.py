"""Shard boundaries must not change forensic strings or canonical types."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from seclogx.case import Case
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.ingest.resources import IngestOptions


def test_timestamp_shaped_text_is_identical_across_conversion_boundaries(tmp_path: Path):
    source = tmp_path / "auth.log"
    messages = ["2026-01-01T00:00:00.000000Z", "plain text"]
    source.write_text("".join(
        f"<34>1 2026-01-01T00:00:00Z original-host sshd 123 - - {message}\n"
        for message in messages
    ), encoding="utf-8")
    results = []
    for name, batch_bytes in [("together", 10000), ("apart", 1)]:
        case = Case.create(name, case_root=tmp_path / "cases")
        report = case.ingest(
            [str(source)], workers=1,
            options=IngestOptions(memory_limit="128MB", threads=1, staging_chunk_bytes=1,
                                  flatten_batch_bytes=batch_bytes),
        )
        assert report.aux.rows_written["syslog"] == 2
        results.append(sorted(case.query("SELECT message FROM syslog")["message"].tolist()))
    assert results[0] == results[1] == sorted(messages)


def test_sparse_batches_keep_json_text_timestamps_and_numeric_casts(tmp_path: Path):
    case = Case.create("sparse", case_root=tmp_path / "cases")
    timestamp_text = "2026-01-01T00:00:00.000000Z"
    extra = json.dumps({"vendor-field": timestamp_text, "custom-count": "000123"})
    rows = [
        {"host": "H", "log_type": "iis", "time_created": timestamp_text,
         "status": 200, "bytes_sent": 123, "username": timestamp_text},
        {"host": "H", "log_type": "iis", "time_created": "bad timestamp",
         "status": "bad integer", "extra": extra},
    ]
    options = IngestOptions(memory_limit="128MB", threads=1)
    for i, row in enumerate(rows):
        path = tmp_path / f"sparse-{i}.ndjson"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        assert flatten_table(case.case_dir, "web_logs", [str(path)], f"batch-{i}",
                             datetime.now(timezone.utc), options=options) == 1
    result = case.query("SELECT * FROM web_logs ORDER BY ingest_batch_id")
    assert result.iloc[0]["username"] == timestamp_text
    assert result.iloc[0]["status"] == 200
    assert result.iloc[0]["bytes_sent"] == 123
    assert result.iloc[0]["time_created"] == pd.Timestamp("2026-01-01")
    assert pd.isna(result.iloc[0]["extra"])
    assert pd.isna(result.iloc[1]["time_created"])
    assert pd.isna(result.iloc[1]["status"])
    assert pd.isna(result.iloc[1]["username"])
    assert result.iloc[1]["extra"] == extra
    extracted = case.query("SELECT extra ->> 'custom-count' AS original FROM web_logs WHERE extra IS NOT NULL")
    assert extracted["original"].iloc[0] == "000123"


def test_exchange_unknown_fields_remain_in_json_catchall(tmp_path: Path):
    source = tmp_path / "exchange.log"
    source.write_text(
        "#Software: Microsoft Exchange Server\n"
        "#Version: 15.0.0.0\n"
        "#Log-type: Message Tracking Log\n"
        "#Fields: date-time,event-id,source,message-id,recipient-address,message-subject,custom-field\n"
        "2026-01-01T00:00:00.000Z,SEND,SMTP,id-1,user@example.test,2026-01-01T00:00:00.000000Z,000123\n",
        encoding="utf-8",
    )
    case = Case.create("exchange", case_root=tmp_path / "cases")
    case.ingest([str(source)], workers=1, options=IngestOptions(staging_chunk_bytes=1, flatten_batch_bytes=1))
    result = case.query("SELECT message_subject, extra ->> 'custom-field' AS custom FROM exchange_message_tracking")
    assert result.iloc[0]["message_subject"] == "2026-01-01T00:00:00.000000Z"
    assert result.iloc[0]["custom"] == "000123"


@pytest.mark.parametrize("together", [True, False])
def test_timestamp_offsets_normalize_to_utc_independently_of_batch(tmp_path: Path, monkeypatch, together):
    pairs = [
        ("2026-09-17T08:12:34+08:00", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-17T00:12:34+00:00", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-16T20:42:34-03:30", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-17T05:42:34+0530", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-17T00:12:34Z", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-17T00:12:34z", datetime(2026, 9, 17, 0, 12, 34)),
        ("2026-09-17T08:12:34.123456+08:00", datetime(2026, 9, 17, 0, 12, 34, 123456)),
        ("2026-09-17T00:12:34.123456Z", datetime(2026, 9, 17, 0, 12, 34, 123456)),
        ("2026-09-17T00:12:34.123456z", datetime(2026, 9, 17, 0, 12, 34, 123456)),
        ("2026-09-16T20:42:34-0330", datetime(2026, 9, 17, 0, 12, 34)),
        # A source with no offset retains its local/unknown wall-clock time.
        ("2026-09-17T12:00:00.654321", datetime(2026, 9, 17, 12, 0, 0, 654321)),
        ("not a timestamp", None),
        ("not a timestamp+08:00", None),
        ("2026-09-17T08:12:34+99:99", None),
        ("2026-09-17T08:12:34+24:00", None),
        ("2026-09-17T08:12:34-2360", None),
        (None, None),
    ]
    original_configure = IngestOptions.configure_connection

    def non_utc_session(options, connection):
        original_configure(options, connection)
        connection.execute("SET TimeZone = 'Asia/Shanghai'")

    monkeypatch.setattr(IngestOptions, "configure_connection", non_utc_session)
    case = Case.create("offsets", case_root=tmp_path / "cases")
    paths = []
    for i, (value, _) in enumerate(pairs):
        path = tmp_path / f"offset-{i}.ndjson"
        path.write_text(json.dumps({"host": "H", "message": str(i), "time_created": value}) + "\n")
        paths.append(str(path))
    batches = [paths] if together else [[path] for path in paths]
    for i, batch in enumerate(batches):
        flatten_table(case.case_dir, "syslog", batch, f"batch-{i}", datetime.now(timezone.utc),
                      options=IngestOptions(memory_limit="128MB", threads=1))
    result = case.query("SELECT message, time_created FROM syslog ORDER BY CAST(message AS INTEGER)")
    assert len(result) == len(pairs)
    for actual, (_, expected) in zip(result["time_created"], pairs):
        if expected is None:
            assert pd.isna(actual)
        else:
            assert actual == expected


def test_web_access_offset_dates_refer_to_same_utc_instant(tmp_path: Path):
    source = tmp_path / "access.log"
    source.write_text(
        '192.0.2.1 - - [17/Sep/2026:08:12:34 +0800] "GET /east HTTP/1.1" 200 42\n'
        '192.0.2.1 - - [16/Sep/2026:20:42:34 -0330] "GET /west HTTP/1.1" 200 42\n'
    )
    case = Case.create("web-time", case_root=tmp_path / "cases")
    report = case.ingest([str(source)], workers=1,
                         options=IngestOptions(staging_chunk_bytes=1, flatten_batch_bytes=1))
    assert report.aux.rows_written["web_logs"] == 2
    result = case.query("SELECT time_created FROM web_logs")
    assert list(result["time_created"]) == [datetime(2026, 9, 17, 0, 12, 34)] * 2
