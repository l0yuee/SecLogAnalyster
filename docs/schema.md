# Normalized event schema

Schema version: `1` (see `schema_version` column). Generated from `src/seclogx/schema.py` -- regenerate this file if that module changes.

Parquet partition columns: `host, channel`.

| Column | Type | Description |
|---|---|---|
| `host` | `VARCHAR` | Analyst-assigned host label (partition key) |
| `channel` | `VARCHAR` | EVTX channel, e.g. 'Security', 'Microsoft-Windows-Sysmon/Operational' (partition key) |
| `provider_name` | `VARCHAR` | Event provider name |
| `provider_guid` | `VARCHAR` | Event provider GUID, nullable |
| `event_id` | `INTEGER` | Windows Event ID |
| `version` | `UTINYINT` | Event ID version, nullable |
| `time_created` | `TIMESTAMP` | Event timestamp (UTC, from System/TimeCreated) |
| `computer` | `VARCHAR` | Hostname embedded in the log itself (may differ from `host`) |
| `record_id` | `BIGINT` | EVTX EventRecordID (unique within source file) |
| `process_id` | `UINTEGER` | Generating process ID, nullable |
| `thread_id` | `UINTEGER` | Generating thread ID, nullable |
| `user_sid` | `VARCHAR` | Security/@UserID SID, nullable |
| `level` | `UTINYINT` | Raw level code |
| `level_name` | `VARCHAR` | Critical/Error/Warning/Information/Verbose, derived |
| `task` | `UINTEGER` | Task code, nullable |
| `opcode` | `UTINYINT` | Opcode, nullable |
| `keywords` | `VARCHAR` | Raw keywords hex bitmask (not decoded in v1) |
| `activity_id` | `VARCHAR` | Correlation/@ActivityID, nullable |
| `related_activity_id` | `VARCHAR` | Correlation/@RelatedActivityID, nullable |
| `event_data` | `JSON` | Flattened EventData (or UserData fallback) Name->Value payload |
| `raw_xml` | `VARCHAR` | Full raw record XML; only populated with --keep-raw |
| `source_path` | `VARCHAR` | Full acquisition path of the source .evtx file |
| `source_file` | `VARCHAR` | Basename of the source .evtx file |
| `file_sha256` | `VARCHAR` | SHA-256 of the source .evtx file (chain of custody) |
| `ingest_batch_id` | `VARCHAR` | UUID of the ingest run that produced this row |
| `ingested_at` | `TIMESTAMP` | Load time |
| `schema_version` | `UTINYINT` | Normalized schema version |

## `event_data`

Holds the provider-specific `EventData` (or `UserData` fallback) Name->Value payload as JSON text. Query individual fields with DuckDB's `->>` operator, e.g.:

```sql
SELECT event_data ->> 'Image', event_data ->> 'CommandLine'
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
```

See `docs/known_limitations.md` for the cases where `event_data` isn't a flat Name->Value dict (legacy unnamed `Data` arrays, `UserData` nesting).
