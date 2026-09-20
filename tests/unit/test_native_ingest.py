"""Optional native batches preserve staging, fallback and source guarantees."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import ModuleType

import pyarrow as pa
import pytest

from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.native import NativeBackendUnavailable, NativeBatchError
from seclogx.ingest.logsources.sniff import KIND_SYSLOG, KIND_WEB_ACCESS
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.ingest.resources import IngestOptions
from seclogx.textdecode import SourceChangedError


class UnsupportedInputError(ValueError):
    pass


def _source(tmp_path: Path) -> ClassifiedFile:
    path = tmp_path / "access.log"
    path.write_text("".join(
        f'192.0.2.1 - - [17/Sep/2026:08:12:34 +0800] "GET /row{i} HTTP/1.1" 200 {i}\n'
        for i in range(3)
    ), encoding="utf-8")
    return ClassifiedFile(path, "HOST", path.stat().st_size, KIND_WEB_ACCESS)


class NativeBatch:
    def __init__(self, row, columns):
        self.batch = pa.RecordBatch.from_pylist([row], schema=pa.schema((c, pa.string()) for c in columns))
        self.encoded_record_sizes = pa.array([len(json.dumps(row).encode()) + 1], type=pa.uint64())

    def __arrow_c_array__(self, requested_schema=None):
        return self.batch.__arrow_c_array__(requested_schema)


def _module(monkeypatch, *, failure=None, mutate=None):
    module = ModuleType("seclogx._native_backend")
    module.API_VERSION = 1
    module.UnsupportedInputError = UnsupportedInputError
    module.readers = []
    module.kwargs = None

    class Reader:
        error_count = 0
        closed = False

        def __init__(self, path, kwargs):
            self.path = Path(path)
            self.kwargs = kwargs
            self.position = 0

        def next_batch(self):
            self.position += 1
            if self.position == 1:
                return NativeBatch({
                    "host": "HOST", "log_type": self.kwargs["log_type"],
                    "uri_stem": "/native-prefix", "status": "200",
                    "source_path": self.kwargs["source_path"],
                    "source_file": self.kwargs["source_file"],
                    "file_sha256": self.kwargs["file_sha256"],
                }, self.kwargs["schema_columns"])
            if mutate:
                mutate(self.path)
            if failure:
                raise failure
            return None

        def close(self):
            self.closed = True

    def open_web_file(path, **kwargs):
        module.kwargs = kwargs
        reader = Reader(path, kwargs)
        module.readers.append(reader)
        return reader

    module.open_web_file = open_web_file
    monkeypatch.setitem(sys.modules, "seclogx._native_backend", module)
    return module


def _rows(result):
    rows = []
    for chunk in result.chunks:
        with pa.memory_map(chunk.path, "r") as source:
            rows.extend(pa.ipc.open_file(source).read_all().to_pylist())
    return rows


def test_optional_component_absent_falls_back_observably(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "seclogx._native_backend", None)
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(parser_backend="auto", staging_format="arrow"))
    assert result.status == "ok"
    assert result.record_count == 3
    assert result.parser_backend == "python"
    assert "unavailable" in result.backend_reason


def test_default_uses_native_batches_with_component_installed(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    options = IngestOptions(staging_format="arrow")
    assert options.parser_backend == "auto"
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging", options)
    assert result.record_count == 1 and result.parser_backend == "native"
    assert module.readers[0].closed


def test_native_batch_is_imported_without_python_row_callbacks(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(staging_format="arrow", parser_backend="native"))
    assert result.status == "ok"
    assert result.parser_backend == "native"
    assert result.backend_reason is None
    assert result.record_count == 1
    assert result.partition_rows == [("HOST", module.kwargs["log_type"])]
    assert isinstance(module.kwargs["source_handle"], int)
    assert module.readers[0].closed
    assert _rows(result)[0]["uri_stem"] == "/native-prefix"


def test_late_unsupported_native_input_discards_all_shards_before_replay(tmp_path, monkeypatch):
    module = _module(monkeypatch, failure=UnsupportedInputError("rare compatible syntax"))
    source = _source(tmp_path)
    staging = tmp_path / "staging"
    result = stage_aux_file(source, staging, IngestOptions(parser_backend="auto",
        staging_format="arrow", staging_chunk_bytes=1,
    ))
    assert result.status == "ok"
    assert result.parser_backend == "python"
    assert "rare compatible syntax" in result.backend_reason
    assert result.record_count == 3
    assert sorted(row["uri_stem"] for row in _rows(result)) == ["/row0", "/row1", "/row2"]
    assert {Path(chunk.path) for chunk in result.chunks} == set(staging.rglob("*.arrow"))
    assert module.readers[0].closed


def test_strict_native_never_silently_replays_python(tmp_path, monkeypatch):
    _module(monkeypatch, failure=UnsupportedInputError("unsupported syntax"))
    source = _source(tmp_path)
    staging = tmp_path / "staging"
    with pytest.raises(NativeBackendUnavailable, match="unsupported syntax"):
        stage_aux_file(source, staging, IngestOptions(staging_format="arrow", parser_backend="native"))
    assert not list(staging.rglob("*.arrow"))


def test_native_io_failure_is_fatal_and_does_not_fallback(tmp_path, monkeypatch):
    module = _module(monkeypatch, failure=OSError("reader failed"))
    source = _source(tmp_path)
    staging = tmp_path / "staging"
    with pytest.raises(OSError, match="reader failed"):
        stage_aux_file(source, staging, IngestOptions(parser_backend="auto", staging_format="arrow"))
    assert not list(staging.rglob("*.arrow"))
    assert module.readers[0].closed


def test_broad_companion_exception_cannot_reclassify_fatal_io(tmp_path, monkeypatch):
    module = _module(monkeypatch, failure=OSError("fatal I/O"))
    module.UnsupportedInputError = Exception
    source = _source(tmp_path)
    staging = tmp_path / "staging"
    with pytest.raises(OSError, match="fatal I/O"):
        stage_aux_file(source, staging, IngestOptions(parser_backend="auto", staging_format="arrow"))
    assert not list(staging.rglob("*.arrow"))
    assert module.readers[0].closed


def test_native_source_change_overrides_compatibility_fallback(tmp_path, monkeypatch):
    module = _module(
        monkeypatch, failure=UnsupportedInputError("mismatch"),
        mutate=lambda path: path.write_bytes(path.read_bytes() + b"changed\n"),
    )
    source = _source(tmp_path)
    staging = tmp_path / "staging"
    with pytest.raises(SourceChangedError):
        stage_aux_file(source, staging, IngestOptions(parser_backend="auto", staging_format="arrow"))
    assert not list(staging.rglob("*.arrow"))
    assert module.readers[0].closed


def test_native_parse_error_keeps_only_accepted_prefix(tmp_path, monkeypatch):
    _module(monkeypatch, failure=ValueError("invalid numeric value"))
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(parser_backend="auto", staging_format="arrow"))
    assert result.status == "partial"
    assert result.parser_backend == "native"
    assert result.record_count == 1
    assert result.error_count == 1
    assert "invalid numeric value" in result.error_message


@pytest.mark.parametrize("malformation", ["schema", "understated-sizes"])
def test_invalid_native_batch_discards_completed_and_current_prefix_shards(tmp_path, monkeypatch, malformation):
    module = _module(monkeypatch)
    original_open = module.open_web_file
    staging = tmp_path / "staging"

    def open_with_invalid_batch(path, **kwargs):
        reader = original_open(path, **kwargs)
        original_next = reader.next_batch
        calls = 0

        def next_batch():
            nonlocal calls
            calls += 1
            if calls <= 2:
                # A one-byte shard target seals the first valid prefix shard
                # when accepting the second. Both must be removed on failure.
                reader.position = 0
                return original_next()
            assert len(list(staging.rglob("*.arrow"))) == 2
            invalid = NativeBatch({"uri_stem": "/bad-contract"}, kwargs["schema_columns"])
            if malformation == "schema":
                invalid.batch = pa.RecordBatch.from_pylist([{"wrong_column": "bad"}])
            else:
                invalid.encoded_record_sizes = pa.array([1], type=pa.uint64())
            return invalid

        reader.next_batch = next_batch
        return reader

    module.open_web_file = open_with_invalid_batch
    with pytest.raises(NativeBatchError, match="invalid native batch") as failure:
        stage_aux_file(_source(tmp_path), staging, IngestOptions(
            staging_format="arrow", staging_chunk_bytes=1, parser_backend="auto",
        ))
    assert isinstance(failure.value.__cause__, ValueError)
    assert module.readers[0].closed
    assert not list(staging.rglob("*.arrow"))
    assert not list(staging.rglob("*.ndjson.gz"))


def test_python_backend_does_not_enter_native(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(staging_format="arrow", parser_backend="python"))
    assert result.status == "ok"
    assert result.parser_backend == "python"
    assert result.backend_reason is None
    assert not module.readers


@pytest.mark.parametrize("backend", ["", "rust", None, True])
def test_invalid_backend_is_rejected(backend):
    with pytest.raises(ValueError, match="parser_backend"):
        IngestOptions(parser_backend=backend)


def _unsupported_source(tmp_path, capability):
    if capability == "format":
        path = tmp_path / "auth.log"
        path.write_text("<34>1 2026-09-18T00:00:00Z host app 12 - - supported by Python\n", encoding="utf-8")
        source = ClassifiedFile(path, "HOST", path.stat().st_size, KIND_SYSLOG)
        return source, "arrow", "unsupported format", 1
    source = _source(tmp_path)
    if capability == "encoding":
        source.path.write_bytes(source.path.read_text(encoding="utf-8").encode("utf-16"))
        source = ClassifiedFile(source.path, source.host, source.path.stat().st_size, source.kind)
        return source, "arrow", "requires validated UTF-8", 3
    return source, "ndjson", "requires Arrow staging", 3


@pytest.mark.parametrize("capability", ["format", "encoding", "ndjson"])
@pytest.mark.parametrize("backend", ["auto", "native"])
def test_unsupported_native_capabilities_are_explicit_before_any_batch(tmp_path, monkeypatch, capability, backend):
    module = _module(monkeypatch)
    source, staging_format, reason, count = _unsupported_source(tmp_path, capability)
    staging = tmp_path / "staging"
    options = IngestOptions(staging_format=staging_format, parser_backend=backend)
    if backend == "native":
        with pytest.raises(NativeBackendUnavailable, match=reason):
            stage_aux_file(source, staging, options)
        assert not list(staging.rglob("*.arrow"))
        assert not list(staging.rglob("*.ndjson.gz"))
    else:
        result = stage_aux_file(source, staging, options)
        assert result.status == "ok"
        assert result.record_count == count
        assert result.parser_backend == "python"
        assert reason in result.backend_reason
        assert result.chunks
    assert module.readers == []
    assert module.kwargs is None


@pytest.mark.parametrize("invalid_api", ["version", "not-a-type", "not-an-exception", "base-exception"])
def test_auto_rejects_an_incompatible_optional_module(tmp_path, monkeypatch, invalid_api):
    module = _module(monkeypatch)
    if invalid_api == "version":
        module.API_VERSION = 2
        reason = "unsupported native API version"
    else:
        module.UnsupportedInputError = {
            "not-a-type": "UnsupportedInputError",
            "not-an-exception": str,
            "base-exception": BaseException,
        }[invalid_api]
        reason = "incomplete native API"
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(staging_format="arrow", parser_backend="auto"))
    assert result.status == "ok"
    assert result.record_count == 3
    assert result.parser_backend == "python"
    assert reason in result.backend_reason
    assert module.readers == []
    assert [row["uri_stem"] for row in _rows(result)] == ["/row0", "/row1", "/row2"]


@pytest.mark.parametrize("constructor_result", ["unsupported", "io-error", "reader"])
def test_source_changed_during_native_constructor_is_fatal(tmp_path, monkeypatch, constructor_result):
    module = _module(monkeypatch)
    source = _source(tmp_path)
    original_open = module.open_web_file

    def change_during_open(path, **kwargs):
        target = Path(path)
        target.write_bytes(target.read_bytes() + b"changed during constructor\n")
        if constructor_result == "unsupported":
            raise UnsupportedInputError("constructor capability mismatch")
        if constructor_result == "io-error":
            raise OSError("constructor read failed")
        return original_open(path, **kwargs)

    module.open_web_file = change_during_open
    staging = tmp_path / "staging"
    with pytest.raises(SourceChangedError):
        stage_aux_file(source, staging, IngestOptions(staging_format="arrow", parser_backend="auto"))
    assert not list(staging.rglob("*.arrow"))
    assert not list(staging.rglob("*.ndjson.gz"))
    assert all(reader.closed for reader in module.readers)


@pytest.mark.parametrize("max_digits", [0, 640, 4300])
def test_native_receives_current_python_integer_limit(tmp_path, monkeypatch, max_digits):
    module = _module(monkeypatch)
    # Patch the adapter's configuration read without changing the interpreter's
    # global integer-conversion policy for other tests.
    monkeypatch.setattr(sys, "get_int_max_str_digits", lambda: max_digits, raising=False)
    result = stage_aux_file(_source(tmp_path), tmp_path / "staging",
                            IngestOptions(staging_format="arrow", parser_backend="native"))
    assert result.status == "ok"
    assert module.kwargs["max_integer_digits"] == max_digits


@pytest.mark.parametrize("invalid_count", ["broken", "0", None, True, False, -1, 0.0])
def test_invalid_native_error_count_is_fatal_after_valid_prefix(tmp_path, monkeypatch, invalid_count):
    module = _module(monkeypatch)
    original_open = module.open_web_file

    def open_with_invalid_count(path, **kwargs):
        reader = original_open(path, **kwargs)
        reader.error_count = invalid_count
        return reader

    module.open_web_file = open_with_invalid_count
    staging = tmp_path / "staging"
    with pytest.raises(NativeBatchError, match="error_count"):
        stage_aux_file(_source(tmp_path), staging, IngestOptions(
            staging_format="arrow", staging_chunk_bytes=1, parser_backend="auto",
        ))
    assert module.readers[0].position == 2  # One accepted batch, then EOF.
    assert module.readers[0].closed
    assert not list(staging.rglob("*.arrow"))
    assert not list(staging.rglob("*.ndjson.gz"))


@pytest.mark.parametrize("failure_type", [AttributeError, ValueError, OSError, UnsupportedInputError])
def test_native_error_count_getter_failure_is_protocol_fatal(tmp_path, monkeypatch, failure_type):
    module = _module(monkeypatch)
    original_open = module.open_web_file
    cause = failure_type("native count getter failed")

    def unreadable_count(reader):
        raise cause

    def open_with_unreadable_count(path, **kwargs):
        reader = original_open(path, **kwargs)
        monkeypatch.setattr(type(reader), "error_count", property(unreadable_count))
        return reader

    module.open_web_file = open_with_unreadable_count
    staging = tmp_path / "staging"
    with pytest.raises(NativeBatchError, match="error_count") as failure:
        stage_aux_file(_source(tmp_path), staging, IngestOptions(
            staging_format="arrow", staging_chunk_bytes=1, parser_backend="auto",
        ))
    assert failure.value.__cause__ is cause
    assert module.readers[0].position == 2
    assert module.readers[0].closed
    assert not list(staging.rglob("*.arrow"))
    assert not list(staging.rglob("*.ndjson.gz"))


def _exception_chain_contains(error, target):
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if current is target:
            return True
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend((current.__cause__, current.__context__))
    return False


@pytest.mark.parametrize("active_kind", ["none", "parse", "unsupported", "io", "protocol"])
def test_native_close_failure_cannot_downgrade_an_active_error(tmp_path, monkeypatch, active_kind):
    active = {
        "none": None,
        "parse": ValueError("source parse failed"),
        "unsupported": UnsupportedInputError("native syntax mismatch"),
        "io": OSError("primary source I/O failed"),
        "protocol": NativeBatchError("primary native protocol failed"),
    }[active_kind]
    if active is not None:
        # Preserving an already-fatal exception also preserves its original
        # cause, rather than replacing that chain with the cleanup failure.
        active.__cause__ = RuntimeError("original failure detail")
    original_cause = active.__cause__ if active is not None else None
    module = _module(monkeypatch, failure=active)
    original_open = module.open_web_file
    close_error = RuntimeError("native close failed")

    def open_with_failed_close(path, **kwargs):
        reader = original_open(path, **kwargs)

        def close():
            reader.closed = True
            raise close_error

        reader.close = close
        return reader

    module.open_web_file = open_with_failed_close
    staging = tmp_path / "staging"
    fatal_type = OSError if active_kind == "io" else NativeBatchError
    with pytest.raises(fatal_type) as failure:
        stage_aux_file(_source(tmp_path), staging, IngestOptions(
            staging_format="arrow", staging_chunk_bytes=1, parser_backend="auto",
        ))
    if active_kind in {"io", "protocol"}:
        assert failure.value is active
        assert failure.value.__cause__ is original_cause
    else:
        assert _exception_chain_contains(failure.value, close_error)
        if active is not None:
            assert _exception_chain_contains(failure.value, active)
    assert module.readers[0].closed
    assert not list(staging.rglob("*.arrow"))
    assert not list(staging.rglob("*.ndjson.gz"))


@pytest.mark.parametrize("kind", ["web_access", "iis"])
def test_real_native_case_matches_python_for_every_query_column(tmp_path, kind):
    pytest.importorskip("seclogx._native_backend")
    import hashlib
    import pandas as pd

    from seclogx import Case
    from seclogx.ingest.logsources.schema import WEB_LOGS_COLUMNS

    source = tmp_path / ("nginx_access.log" if kind == "web_access" else "iis.log")
    if kind == "web_access":
        content = (
            '192.0.2.1 - alice [18/Sep/2026:08:12:34 +0800] "GET /中文?q=1 HTTP/1.1" 200 00012 "-" "UA"\n'
            'not a log record\n'
            '192.0.2.2 - - [18/Sep/2026:08:12:35 -0330] "POST /second HTTP/1.1" 404 - "https://example.invalid/" "-"\n'
        )
    else:
        content = (
            "#Software: Microsoft Internet Information Services\n"
            "#Fields: date time c-ip s-port cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs-username cs(User-Agent) x-note\n"
            "2026-09-18 08:12:34 192.0.2.1 080 GET /中文 q=1 0200 00012 alice UA 文档\n"
            "wrong field count\n"
            "2026-09-18 08:12:35 192.0.2.2 443 POST /second - 404 - - - -\n"
        )
    source.write_text(content, encoding="utf-8")
    columns = [name for name, _ in WEB_LOGS_COLUMNS]
    expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    results = []
    for backend in ("python", "native"):
        case = Case.create(backend, case_root=tmp_path / "cases")
        progress = []
        report = case.ingest([str(source)], workers=1, on_progress=progress.append,
                             options=IngestOptions(staging_format="arrow", parser_backend=backend,
                                                   memory_limit="256MB", threads=1, staging_chunk_bytes=1024))
        assert report.aux.rows_written == {"web_logs": 2}
        assert report.aux.files_partial == 1
        assert report.aux.staged_files[0].parser_backend == backend
        assert report.aux.staged_files[0].backend_reason is None
        assert progress[-1]["phase"] == "done"
        assert progress[-1]["rows_written"] == {"web_logs": 2}
        with case:
            result = case.query("SELECT * FROM web_logs ORDER BY source_file, uri_stem")
        assert set(result.columns) == set(columns)
        result = result[columns].copy()
        assert set(result.file_sha256) == {expected_hash}
        assert set(result.source_path) == {str(source)}
        assert set(result.source_file) == {source.name}
        assert set(result.ingest_batch_id) == {report.aux.batch_id}
        assert result.ingested_at.notna().all()
        assert result.ingested_at.nunique() == 1
        assert set(result.schema_version) == {1}
        # These two values identify independent ingest runs; validate them
        # above, then compare the entire canonical column set after rebasing.
        result["ingest_batch_id"] = "<independent-ingest>"
        result["ingested_at"] = pd.Timestamp("2000-01-01")
        results.append(result)
    pd.testing.assert_frame_equal(results[0], results[1])
