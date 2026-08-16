"""Canonical normalized event schema.

This module is the single source of truth for the columns that make up a
normalized event row. `docs/schema.md` is generated from / kept in sync with
this file.

Column extraction expressions were validated empirically against real
sample .evtx files (Sysmon, Security, System channels) covering the
observed shape variance of EVTX-as-JSON:

- `EventID` is sometimes a bare int, sometimes an object with a `#text`
  child (legacy qualified event IDs, e.g. classic System/Application
  channel events).
- `EventData` is usually a flat Name->Value dict (modern providers,
  including Sysmon) but can be null, or wrap unnamed values under a
  `Data` key (legacy System channel events without named fields).
- `UserData` (common for providers like TerminalServices,
  Defender/Windows Defender, Task Scheduler) wraps its fields one level
  under a provider-specific root element name rather than being flat.
  v1 stores it as-is under `event_data` for full-text search; per-field
  Sigma mapping for UserData-based providers is a known limitation
  (see docs/known_limitations.md).

Extraction uses DuckDB's chained `->`/`->>` JSON operators rather than
JSONPath strings, since `#`-prefixed keys are awkward to express safely in
JSONPath syntax.
"""

from __future__ import annotations

SCHEMA_VERSION = 1

# (column_name, duckdb_type, description)
CORE_COLUMNS: list[tuple[str, str, str]] = [
    ("host", "VARCHAR", "Analyst-assigned host label (partition key)"),
    ("channel", "VARCHAR", "EVTX channel, e.g. 'Security', 'Microsoft-Windows-Sysmon/Operational' (partition key)"),
    ("provider_name", "VARCHAR", "Event provider name"),
    ("provider_guid", "VARCHAR", "Event provider GUID, nullable"),
    ("event_id", "INTEGER", "Windows Event ID"),
    ("version", "UTINYINT", "Event ID version, nullable"),
    ("time_created", "TIMESTAMP", "Event timestamp (UTC, from System/TimeCreated)"),
    ("computer", "VARCHAR", "Hostname embedded in the log itself (may differ from `host`)"),
    ("record_id", "BIGINT", "EVTX EventRecordID (unique within source file)"),
    ("process_id", "UINTEGER", "Generating process ID, nullable"),
    ("thread_id", "UINTEGER", "Generating thread ID, nullable"),
    ("user_sid", "VARCHAR", "Security/@UserID SID, nullable"),
    ("level", "UTINYINT", "Raw level code"),
    ("level_name", "VARCHAR", "Critical/Error/Warning/Information/Verbose, derived"),
    ("task", "UINTEGER", "Task code, nullable"),
    ("opcode", "UTINYINT", "Opcode, nullable"),
    ("keywords", "VARCHAR", "Raw keywords hex bitmask (not decoded in v1)"),
    ("activity_id", "VARCHAR", "Correlation/@ActivityID, nullable"),
    ("related_activity_id", "VARCHAR", "Correlation/@RelatedActivityID, nullable"),
    ("event_data", "JSON", "Flattened EventData (or UserData fallback) Name->Value payload"),
    ("raw_xml", "VARCHAR", "Full raw record XML; only populated with --keep-raw"),
    ("source_path", "VARCHAR", "Full acquisition path of the source .evtx file"),
    ("source_file", "VARCHAR", "Basename of the source .evtx file"),
    ("file_sha256", "VARCHAR", "SHA-256 of the source .evtx file (chain of custody)"),
    ("ingest_batch_id", "VARCHAR", "UUID of the ingest run that produced this row"),
    ("ingested_at", "TIMESTAMP", "Load time"),
    ("schema_version", "UTINYINT", "Normalized schema version"),
]

COLUMN_NAMES: list[str] = [c[0] for c in CORE_COLUMNS]

# SQL expressions extracting each field from the staged raw columns:
#   raw.event_record_id  BIGINT  -- authoritative record id from the evtx parser
#   raw.data              VARCHAR -- JSON string of the full record (records_json())
# Provenance columns (host, source_path, source_file, file_sha256,
# ingest_batch_id, ingested_at) are supplied by a join against the staging
# manifest in ingest/flatten.py, not derived from `data`.
EXTRACTION_SQL: dict[str, str] = {
    "channel": "data -> 'Event' -> 'System' ->> 'Channel'",
    "provider_name": "data -> 'Event' -> 'System' -> 'Provider' -> '#attributes' ->> 'Name'",
    "provider_guid": "data -> 'Event' -> 'System' -> 'Provider' -> '#attributes' ->> 'Guid'",
    "event_id": (
        "COALESCE("
        "TRY_CAST(data -> 'Event' -> 'System' -> 'EventID' AS INTEGER), "
        "TRY_CAST(data -> 'Event' -> 'System' -> 'EventID' -> '#text' AS INTEGER)"
        ")"
    ),
    "version": "TRY_CAST(data -> 'Event' -> 'System' -> 'Version' AS UTINYINT)",
    "time_created": (
        "TRY_CAST(data -> 'Event' -> 'System' -> 'TimeCreated' -> '#attributes' ->> 'SystemTime' AS TIMESTAMP)"
    ),
    "computer": "data -> 'Event' -> 'System' ->> 'Computer'",
    "record_id": "raw.event_record_id",
    "process_id": "TRY_CAST(data -> 'Event' -> 'System' -> 'Execution' -> '#attributes' ->> 'ProcessID' AS UINTEGER)",
    "thread_id": "TRY_CAST(data -> 'Event' -> 'System' -> 'Execution' -> '#attributes' ->> 'ThreadID' AS UINTEGER)",
    "user_sid": "data -> 'Event' -> 'System' -> 'Security' -> '#attributes' ->> 'UserID'",
    "level": "TRY_CAST(data -> 'Event' -> 'System' -> 'Level' AS UTINYINT)",
    "level_name": (
        "CASE TRY_CAST(data -> 'Event' -> 'System' -> 'Level' AS UTINYINT) "
        "WHEN 1 THEN 'Critical' WHEN 2 THEN 'Error' WHEN 3 THEN 'Warning' "
        "WHEN 4 THEN 'Information' WHEN 5 THEN 'Verbose' ELSE NULL END"
    ),
    "task": "TRY_CAST(data -> 'Event' -> 'System' -> 'Task' AS UINTEGER)",
    "opcode": "TRY_CAST(data -> 'Event' -> 'System' -> 'Opcode' AS UTINYINT)",
    "keywords": "data -> 'Event' -> 'System' ->> 'Keywords'",
    "activity_id": "data -> 'Event' -> 'System' -> 'Correlation' -> '#attributes' ->> 'ActivityID'",
    "related_activity_id": "data -> 'Event' -> 'System' -> 'Correlation' -> '#attributes' ->> 'RelatedActivityID'",
    # Explicitly cast to VARCHAR: an all-NULL EventData/UserData partition (e.g. a
    # channel where it's always absent) would otherwise let DuckDB's Parquet writer
    # infer a different physical column type than partitions with real JSON content,
    # breaking `union_by_name` reads across the lake (validated empirically).
    "event_data": "CAST(COALESCE(data -> 'Event' -> 'EventData', data -> 'Event' -> 'UserData') AS VARCHAR)",
    "raw_xml": "raw_xml",
    "schema_version": str(SCHEMA_VERSION),
}

# Columns supplied via join against the staging manifest, not extracted from `data`.
PROVENANCE_COLUMNS = ["host", "source_path", "source_file", "file_sha256", "ingest_batch_id", "ingested_at"]

PARTITION_COLUMNS = ["host", "channel"]
