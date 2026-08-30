from __future__ import annotations

import pytest

from seclogx.ingest.logsources.schema import TABLES, cast_sql_for


def test_tables_registry_has_expected_tables():
    assert set(TABLES) == {
        "web_logs",
        "web_error_logs",
        "scheduled_tasks",
        "exchange_message_tracking",
        "exchange_logs",
    }
    for table, definition in TABLES.items():
        assert "columns" in definition
        assert "partition_by" in definition
        column_names = {c for c, _ in definition["columns"]}
        assert set(definition["partition_by"]) <= column_names


def test_cast_sql_for_covers_every_declared_column():
    for table in TABLES:
        cast_sql = cast_sql_for(table)
        expected_columns = {c for c, _ in TABLES[table]["columns"]}
        assert set(cast_sql) == expected_columns


def test_cast_sql_for_uses_cast_not_try_cast_for_json_and_text_catchalls():
    cast_sql = cast_sql_for("scheduled_tasks")
    # actions/triggers are declared JSON but physically stored as VARCHAR
    # (see the module docstring) -- must be a plain CAST, not TRY_CAST,
    # and never reference the declared JSON type directly.
    assert cast_sql["actions"] == "CAST(raw.actions AS VARCHAR)"
    assert cast_sql["triggers"] == "CAST(raw.triggers AS VARCHAR)"


def test_cast_sql_for_uses_try_cast_for_typed_columns():
    cast_sql = cast_sql_for("web_logs")
    assert cast_sql["status"] == "TRY_CAST(raw.status AS INTEGER)"
    assert cast_sql["time_created"] == "TRY_CAST(raw.time_created AS TIMESTAMP)"
    assert cast_sql["bytes_sent"] == "TRY_CAST(raw.bytes_sent AS BIGINT)"


def test_cast_sql_for_varchar_columns_use_cast():
    cast_sql = cast_sql_for("web_logs")
    assert cast_sql["host"] == "CAST(raw.host AS VARCHAR)"
    assert cast_sql["client_ip"] == "CAST(raw.client_ip AS VARCHAR)"


def test_cast_sql_for_unknown_table_raises_key_error():
    with pytest.raises(KeyError):
        cast_sql_for("does_not_exist")
