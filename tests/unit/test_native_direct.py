"""Direct-output semantic and failure-boundary regressions."""
from __future__ import annotations

from datetime import datetime, timezone
import dataclasses
import json
from pathlib import Path
import sys
from types import ModuleType

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from seclogx.ingest.logsources import direct
from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.flatten import flatten_table
from seclogx.ingest.logsources.native import NativeBackendUnavailable, NativeBatchError
from seclogx.ingest.logsources.sniff import KIND_IIS, KIND_WEB_ACCESS
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.ingest.resources import CONVERSION_LOCK, IngestOptions
from seclogx.textdecode import SourceChangedError, prepare_text


WHEN = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


class UnsupportedInputError(ValueError):
    pass


class Batch:
    def __init__(self, rows, columns):
        self.batch = pa.RecordBatch.from_pylist(rows, schema=pa.schema((name, pa.string()) for name in columns))
        self.encoded_record_sizes = pa.array([
            len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode()) + 1 for row in rows
        ], type=pa.uint64())

    def __arrow_c_array__(self, requested_schema=None):
        return self.batch.__arrow_c_array__(requested_schema)


def source(tmp_path, *, host="HOST"):
    path = tmp_path / "access.log"
    path.write_text('192.0.2.1 - - [18/Sep/2026:12:34:56 +0800] "GET /hello HTTP/1.1" 200 123\n',
                    encoding="utf-8")
    return ClassifiedFile(path, host, path.stat().st_size, KIND_WEB_ACCESS)


def install(monkeypatch, *, failure=None, error_count=0, close_error=None,
            before_end=None, row_updates=None, empty_first=False, no_rows=False):
    module = ModuleType("seclogx._native_backend")
    module.API_VERSION = 1
    module.UnsupportedInputError = UnsupportedInputError
    module.readers = []

    class Reader:
        closed = False

        def __init__(self, path, values):
            self.path = Path(path)
            self.values = values
            self.position = 0
            self.error_count = error_count

        def next_batch(self):
            position = self.position
            self.position += 1
            if empty_first and position == 0:
                return Batch([], self.values["schema_columns"])
            if position == int(empty_first) and not no_rows:
                row = {
                    "host": self.values["host"], "log_type": self.values["log_type"],
                    "time_created": "2026-09-18T12:34:56+08:00", "status": "200", "bytes_sent": "123",
                    "uri_stem": "/hello", "extra": '{"unknown": "保留"}',
                    "source_path": self.values["source_path"], "source_file": self.values["source_file"],
                    "file_sha256": self.values["file_sha256"],
                }
                row.update(row_updates or {})
                return Batch([row], self.values["schema_columns"])
            if before_end:
                before_end(self)
            if failure:
                raise failure
            return None

        def close(self):
            self.closed = True
            if close_error:
                raise close_error

    def open_web_file(path, **values):
        reader = Reader(path, values)
        module.readers.append(reader)
        return reader

    module.open_web_file = open_web_file
    monkeypatch.setitem(sys.modules, "seclogx._native_backend", module)
    return module


def convert(cf, case, **kwargs):
    return direct.direct_web_file(cf, case, "batch'quoted", WHEN,
                                  kwargs.pop("options", IngestOptions(parser_backend="auto")), **kwargs)


def rows(case):
    with duckdb.connect() as con:
        return con.execute("SELECT * FROM read_parquet(?, hive_partitioning=true, union_by_name=true)",
                           [str(case / "lake" / "web_logs" / "**" / "*.parquet")]).fetchall()


def assert_private_clean(case):
    private = case / "_ingest_private"
    assert not private.exists() or list(private.iterdir()) == []


def test_direct_matches_existing_native_staging_conversion(tmp_path, monkeypatch):
    module = install(monkeypatch)
    cf = source(tmp_path)
    result = convert(cf, tmp_path / "direct")
    staged = stage_aux_file(cf, tmp_path / "staging", IngestOptions(staging_format="arrow", parser_backend="auto"))
    flatten_table(tmp_path / "reference", "web_logs", [chunk.path for chunk in staged.chunks],
                  "batch'quoted", WHEN, partition_rows=staged.partition_rows)
    assert rows(tmp_path / "direct") == rows(tmp_path / "reference")
    assert result.rows_written == result.staged_file.record_count == 1
    assert result.staged_file.output_format == "parquet"
    assert result.staged_file.parquet_paths == [result.parquet_path]
    assert result.staged_file.ndjson_path is None and result.staged_file.chunks == []
    assert all(reader.closed for reader in module.readers)
    assert "host" not in pq.read_schema(result.parquet_path).names
    assert "log_type" not in pq.read_schema(result.parquet_path).names
    assert_private_clean(tmp_path / "direct")


def test_private_prefix_is_not_visible_before_source_finishes(tmp_path, monkeypatch):
    case = tmp_path / "case"

    def inspect(reader):
        assert not list((case / "lake").rglob("*.parquet"))
        assert list((case / "_ingest_private").iterdir())

    install(monkeypatch, before_end=inspect)
    result = convert(source(tmp_path), case)
    assert result.rows_written == 1 and Path(result.parquet_path).is_file()


def test_empty_scan_batch_does_not_end_direct_stream(tmp_path, monkeypatch):
    install(monkeypatch, empty_first=True)
    assert convert(source(tmp_path), tmp_path / "case").rows_written == 1


@pytest.mark.parametrize("errors", [0, 3])
def test_no_valid_records_publish_nothing(tmp_path, monkeypatch, errors):
    install(monkeypatch, no_rows=True, error_count=errors)
    case = tmp_path / "case"
    result = convert(source(tmp_path), case)
    assert result.staged_file.status == "failed"
    assert result.staged_file.error_count == errors
    assert result.rows_written == 0 and result.parquet_path is None
    assert not list((case / "lake").rglob("*.parquet"))
    assert_private_clean(case)


def test_partial_parse_error_publishes_only_accepted_prefix(tmp_path, monkeypatch):
    install(monkeypatch, failure=ValueError("invalid bytes value"), error_count=3)
    result = convert(source(tmp_path), tmp_path / "case")
    assert result.staged_file.status == "partial" and result.rows_written == 1
    assert result.staged_file.error_count == 1
    assert "invalid bytes value" in result.staged_file.error_message


def test_format_rejections_keep_full_row_count_and_partial_status(tmp_path, monkeypatch):
    install(monkeypatch, error_count=4)
    result = convert(source(tmp_path), tmp_path / "case")
    assert result.staged_file.status == "partial" and result.rows_written == 1
    assert result.staged_file.error_count == 4


def test_late_unsupported_cleans_private_output_and_reuses_prepared(tmp_path, monkeypatch):
    install(monkeypatch, failure=UnsupportedInputError("rare time spelling"))
    cf, case = source(tmp_path), tmp_path / "case"
    prepared = prepare_text(cf.path)
    monkeypatch.setattr(direct, "prepare_text", lambda *args: pytest.fail("must reuse preparation"))
    result = convert(cf, case, prepared=prepared)
    assert result.staged_file is None and result.prepared is prepared
    assert "rare time spelling" in result.fallback_reason
    assert result.rows_written == 0 and result.parquet_path is None
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))


def test_strict_native_capability_failure_cleans_private_output(tmp_path, monkeypatch):
    install(monkeypatch, failure=UnsupportedInputError("unsupported syntax"))
    case = tmp_path / "case"
    with pytest.raises(NativeBackendUnavailable, match="unsupported syntax"):
        convert(source(tmp_path), case, options=IngestOptions(parser_backend="native"))
    assert_private_clean(case)


@pytest.mark.parametrize("failure", [OSError("read failure"), RuntimeError("unexpected parser failure")])
def test_read_failure_is_fatal(tmp_path, monkeypatch, failure):
    module = install(monkeypatch, failure=failure)
    case = tmp_path / "case"
    with pytest.raises(type(failure), match=str(failure)):
        convert(source(tmp_path), case)
    assert module.readers[0].closed
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))


@pytest.mark.parametrize("close_error", [ValueError("broken close"), OSError("broken close")])
def test_reader_close_failure_does_not_publish_or_fallback(tmp_path, monkeypatch, close_error):
    install(monkeypatch, close_error=close_error, failure=UnsupportedInputError("capability mismatch"))
    case = tmp_path / "case"
    with pytest.raises((NativeBatchError, OSError), match="broken close"):
        convert(source(tmp_path), case)
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))


def test_source_change_overrides_capability_fallback(tmp_path, monkeypatch):
    install(monkeypatch, failure=UnsupportedInputError("unsupported"),
            before_end=lambda reader: reader.path.write_bytes(reader.path.read_bytes() + b"changed\n"))
    case = tmp_path / "case"
    with pytest.raises(SourceChangedError):
        convert(source(tmp_path), case)
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))


@pytest.mark.parametrize("column,value", [("host", "WRONG"), ("host", None), ("log_type", "WRONG")])
def test_fixed_partition_mismatch_is_fatal(tmp_path, monkeypatch, column, value):
    install(monkeypatch, row_updates={column: value})
    case = tmp_path / "case"
    with pytest.raises(NativeBatchError, match="fixed"):
        convert(source(tmp_path), case)
    assert_private_clean(case)


@pytest.mark.parametrize("errors", [None, True, -1, "4", 1.5])
def test_invalid_terminal_error_metadata_is_fatal(tmp_path, monkeypatch, errors):
    install(monkeypatch, error_count=errors)
    case = tmp_path / "case"
    with pytest.raises(NativeBatchError, match="error_count"):
        convert(source(tmp_path), case)
    assert_private_clean(case)


def test_unsupported_reader_constructor_returns_fallback(tmp_path, monkeypatch):
    module = install(monkeypatch)
    module.open_web_file = lambda *args, **kwargs: (_ for _ in ()).throw(UnsupportedInputError("constructor"))
    result = convert(source(tmp_path), tmp_path / "case")
    assert result.staged_file is None and "constructor" in result.fallback_reason
    assert_private_clean(tmp_path / "case")


def test_sql_failure_is_not_a_parser_fallback(tmp_path, monkeypatch):
    module = install(monkeypatch)
    module.UnsupportedInputError = Exception
    monkeypatch.setattr(direct, "build_select_query", lambda *args: "SELECT unknown_column FROM direct_arrow")
    case = tmp_path / "case"
    with pytest.raises(duckdb.Error):
        convert(source(tmp_path), case)
    assert_private_clean(case)


def test_partition_values_are_escaped_as_single_components(tmp_path, monkeypatch):
    install(monkeypatch)
    host = "../主机/percent%quoted'"
    case = tmp_path / "case"
    result = convert(source(tmp_path, host=host), case)
    path = Path(result.parquet_path)
    assert path.is_relative_to(case / "lake" / "web_logs")
    assert "%2F" in path.parent.parent.name
    with duckdb.connect() as con:
        assert con.execute("SELECT host FROM read_parquet(?, hive_partitioning=true)",
                           [str(path)]).fetchone() == (host,)


@pytest.mark.parametrize("change", ["path", "policy"])
def test_prepared_identity_and_policy_must_match(tmp_path, monkeypatch, change):
    install(monkeypatch)
    cf = source(tmp_path)
    prepared = prepare_text(cf.path)
    changes = {"path": tmp_path / "other.log"} if change == "path" else {"utf16_requires_bom": True}
    with pytest.raises(ValueError, match="prepared source"):
        convert(cf, tmp_path / "case", prepared=dataclasses.replace(prepared, **changes))


def test_conversion_lock_covers_configuration_and_connection_close(tmp_path, monkeypatch):
    install(monkeypatch)
    original = direct.duckdb.connect
    events = []

    class Connection:
        def __init__(self):
            assert CONVERSION_LOCK.locked()
            self.real = original()

        def __enter__(self):
            events.append("enter")
            assert CONVERSION_LOCK.locked()
            return self

        def __exit__(self, *args):
            assert CONVERSION_LOCK.locked()
            events.append("close")
            self.real.close()

        def __getattr__(self, name):
            return getattr(self.real, name)

    monkeypatch.setattr(direct.duckdb, "connect", Connection)
    result = convert(source(tmp_path), tmp_path / "case")
    assert result.rows_written == 1 and events == ["enter", "close"]
    assert not CONVERSION_LOCK.locked()


@pytest.mark.parametrize("fault", ["copy", "count", "close"])
def test_conversion_failures_never_publish_a_private_prefix(tmp_path, monkeypatch, fault):
    install(monkeypatch)
    original = direct.duckdb.connect

    class Connection:
        def __init__(self):
            self.real = original()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.real.close()
            if fault == "close":
                raise OSError("connection close failure")

        def __getattr__(self, name):
            return getattr(self.real, name)

        def execute(self, sql, *args):
            if sql.startswith("COPY") and fault == "copy":
                raise OSError("Parquet write failure")
            result = self.real.execute(sql, *args)
            if sql.startswith("COPY") and fault == "count":
                class Count:
                    def fetchone(self):
                        return (999,)
                return Count()
            return result

    monkeypatch.setattr(direct.duckdb, "connect", Connection)
    case = tmp_path / "case"
    with pytest.raises((OSError, NativeBatchError)):
        convert(source(tmp_path), case)
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))
    assert not CONVERSION_LOCK.locked()


@pytest.mark.parametrize("primary_fault", ["copy", "native"])
def test_conversion_and_cleanup_errors_both_remain_traceable(tmp_path, monkeypatch, primary_fault):
    primary = OSError(f"original {primary_fault} failure")
    module = install(monkeypatch, failure=primary if primary_fault == "native" else None)
    original_connect = direct.duckdb.connect
    original_stack = direct.ExitStack
    cleanup = []

    class ObservedStack(original_stack):
        def callback(self, function, *args, **kwargs):
            def observed():
                cleanup.append(function.__name__)
                return function(*args, **kwargs)
            return super().callback(observed)

    class Connection:
        def __init__(self):
            self.real = original_connect()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            cleanup.append("connection_close")
            self.real.close()

        def __getattr__(self, name):
            return getattr(self.real, name)

        def execute(self, sql, *args):
            if sql.startswith("COPY") and primary_fault == "copy":
                raise primary
            return self.real.execute(sql, *args)

        def unregister(self, name):
            self.real.unregister(name)
            raise ValueError("unregister cleanup failure")

    monkeypatch.setattr(direct, "ExitStack", ObservedStack)
    monkeypatch.setattr(direct.duckdb, "connect", Connection)
    case = tmp_path / "case"
    with pytest.raises(ValueError, match="unregister cleanup failure") as caught:
        convert(source(tmp_path), case)
    pending, seen, chain = [caught.value], set(), []
    while pending:
        error = pending.pop()
        if error is None or id(error) in seen:
            continue
        seen.add(id(error))
        chain.append(error)
        pending.extend((error.__cause__, error.__context__))
    assert primary in chain
    assert cleanup == ["unregister", "close", "close", "connection_close"]
    assert module.readers[0].closed
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))
    assert not CONVERSION_LOCK.locked()


def test_initial_preparation_failure_is_a_failed_source(tmp_path, monkeypatch):
    cf = source(tmp_path)
    case = tmp_path / "case"
    monkeypatch.setattr(direct, "prepare_text", lambda *args: (_ for _ in ()).throw(OSError("unreadable")))
    result = convert(cf, case)
    assert result.prepared is None and result.staged_file.status == "failed"
    assert result.staged_file.parser_backend == "none"
    assert result.staged_file.file_sha256 == "" and result.staged_file.table is None
    assert result.staged_file.parquet_paths == [] and result.rows_written == 0
    assert not case.exists()


def test_publication_failure_cleans_the_source_private_directory(tmp_path, monkeypatch):
    install(monkeypatch)
    original = Path.rename

    def fail_publication(path, target):
        if path.name == "part.parquet":
            raise OSError("publication denied")
        return original(path, target)

    if direct.os.name == "nt":
        monkeypatch.setattr(Path, "rename", fail_publication)
    else:
        monkeypatch.setattr(direct.os, "link", lambda *args: (_ for _ in ()).throw(OSError("publication denied")))
    case = tmp_path / "case"
    with pytest.raises(OSError, match="publication denied"):
        convert(source(tmp_path), case)
    assert_private_clean(case)
    assert not list((case / "lake").rglob("*.parquet"))


def test_preexisting_uuid_destination_is_never_overwritten(tmp_path, monkeypatch):
    module = install(monkeypatch)
    cf, case = source(tmp_path), tmp_path / "case"
    identifier = direct.uuid.UUID("12345678-1234-4234-8234-123456789abc")
    monkeypatch.setattr(direct.uuid, "uuid4", lambda: identifier)
    first = convert(cf, case)
    expected_bytes = Path(first.parquet_path).read_bytes()
    with pytest.raises(FileExistsError):
        convert(cf, case)
    assert Path(first.parquet_path).read_bytes() == expected_bytes
    assert len(module.readers) == 2
    assert_private_clean(case)


@pytest.mark.parametrize("kind,text", [
    (KIND_WEB_ACCESS,
     '192.0.2.1 - user [18/Sep/2026:12:34:56 +0800] "GET /保留?q=值 HTTP/1.1" 200 123 "-" "agent"\n'),
    (KIND_IIS,
     '#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes x-extra\n'
     '2026-09-18 12:34:56 192.0.2.1 GET /保留 200 123 自定义\n'),
])
def test_installed_native_direct_matches_python_canonical_rows(tmp_path, kind, text):
    pytest.importorskip("seclogx._native_backend")
    path = tmp_path / "native_access.log"
    path.write_text(text, encoding="utf-8")
    cf = ClassifiedFile(path, "REAL_NATIVE", path.stat().st_size, kind)
    result = convert(cf, tmp_path / "direct", options=IngestOptions(parser_backend="native"))
    staged = stage_aux_file(cf, tmp_path / "staging",
                            IngestOptions(parser_backend="python", staging_format="arrow"))
    flatten_table(tmp_path / "python", "web_logs", [chunk.path for chunk in staged.chunks],
                  "batch'quoted", WHEN, partition_rows=staged.partition_rows)
    assert result.rows_written == 1
    assert rows(tmp_path / "direct") == rows(tmp_path / "python")


def test_installed_native_direct_never_calls_ipc_or_row_writers(tmp_path, monkeypatch):
    pytest.importorskip("seclogx._native_backend")

    def forbidden(*args, **kwargs):
        pytest.fail("direct conversion attempted staging or a Python row writer")

    for name in ("write", "write_batch", "_write_arrow_batch"):
        monkeypatch.setattr(direct.ArrowStagingWriter, name, forbidden)
    monkeypatch.setattr(pa.ipc, "new_file", forbidden)
    monkeypatch.setattr(pa.ipc, "new_stream", forbidden)
    case = tmp_path / "case"
    result = convert(source(tmp_path), case, options=IngestOptions(parser_backend="native"))
    assert result.rows_written == 1
    assert {path for path in case.rglob("*") if path.is_file()} == {Path(result.parquet_path)}
    assert_private_clean(case)
