"""Automatic batch parser adapter; Python remains the compatibility path.

Native producers and Arrow consumers run in the same file worker or direct
conversion coordinator. Only the source manifest crosses a process boundary,
never Arrow buffer pointers.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import importlib
import os
import sys
from types import ModuleType
from typing import Iterator

import pyarrow as pa

from ...textdecode import PreparedText, _verify_prepared
from ..arrow_staging import ArrowStagingWriter
from ..resources import IngestOptions
from .discovery import ClassifiedFile
from .sniff import KIND_IIS, KIND_WEB_ACCESS, guess_web_log_type


class NativeBackendUnavailable(RuntimeError):
    """An explicitly requested native parser cannot handle this source."""


class NativeBatchError(RuntimeError):
    """The companion violated the batch contract; do not publish a prefix."""


@dataclass(frozen=True)
class NativeSelection:
    module: ModuleType | None
    reason: str | None = None


def load_native_component() -> NativeSelection:
    """Probe the extension API without reading or hashing a source file."""
    try:
        module = importlib.import_module("seclogx._native_backend")
    except (ImportError, OSError) as exc:
        return NativeSelection(None, f"native component unavailable: {exc}")
    if getattr(module, "API_VERSION", None) != 1:
        return NativeSelection(None, "unsupported native API version")
    unsupported = getattr(module, "UnsupportedInputError", None)
    if (not callable(getattr(module, "open_web_file", None))
            or not isinstance(unsupported, type)
            or not issubclass(unsupported, Exception)):
        return NativeSelection(None, "incomplete native API")
    return NativeSelection(module)


def select_native_parser(
    cf: ClassifiedFile, prepared: PreparedText | None,
    options: IngestOptions, *, arrow_staging: bool,
) -> NativeSelection:
    """Choose before emitting rows, with an observable auto fallback reason."""
    if options.parser_backend == "python":
        return NativeSelection(None)

    def unavailable(reason: str) -> NativeSelection:
        if options.parser_backend == "native":
            raise NativeBackendUnavailable(f"native parser unavailable for {cf.path}: {reason}")
        return NativeSelection(None, reason)

    if cf.kind not in (KIND_IIS, KIND_WEB_ACCESS):
        return unavailable("unsupported format")
    if prepared is None or prepared.encoding not in ("utf-8", "utf-8-sig"):
        return unavailable("native parser requires validated UTF-8")
    if not arrow_staging:
        return unavailable("native parser requires Arrow staging")
    selection = load_native_component()
    if selection.module is None:
        return unavailable(selection.reason)
    return selection


@contextmanager
def native_reader(
    module: ModuleType, cf: ClassifiedFile, prepared: PreparedText,
    writer: ArrowStagingWriter,
) -> Iterator:
    """Keep a verified source handle alive until the native reader closes.

    The extension duplicates this handle; it must not take ownership of Python's
    descriptor. Path and descriptor identity checks also run on exceptional exit.
    """
    with cf.path.open("rb") as source:
        _verify_prepared(prepared, source)
        if os.name == "nt":
            import msvcrt
            handle = msvcrt.get_osfhandle(source.fileno())
        else:
            handle = source.fileno()
        reader = None
        active_error = None
        try:
            reader = module.open_web_file(
                str(cf.path), kind="iis" if cf.kind == KIND_IIS else "web_access",
                host=cf.host, log_type="iis" if cf.kind == KIND_IIS else guess_web_log_type(cf.path),
                source_path=str(cf.path), source_file=cf.path.name,
                file_sha256=prepared.sha256, schema_columns=writer.schema.names,
                max_batch_bytes=min(writer.chunk_bytes, writer.max_batch_bytes),
                max_batch_rows=writer.max_batch_rows, max_line_chars=8 * 1024 * 1024,
                max_record_bytes=writer.max_record_bytes, source_handle=handle,
                max_integer_digits=getattr(sys, "get_int_max_str_digits", lambda: 0)(),
            )
            yield reader
        except BaseException as exc:
            active_error = exc
            raise
        finally:
            try:
                if reader is not None:
                    try:
                        reader.close()
                    except BaseException as exc:
                        if isinstance(active_error, (OSError, NativeBatchError)) or (
                            active_error is not None and not isinstance(active_error, Exception)
                        ):
                            # Preserve the original fatal error/cancellation;
                            # a broken close must never turn it into partial.
                            pass
                        elif isinstance(exc, OSError) or not isinstance(exc, Exception):
                            raise
                        else:
                            raise NativeBatchError(f"native reader close failed for {cf.path}: {exc}") from exc
            finally:
                _verify_prepared(prepared, source)


def read_native_error_count(reader) -> int:
    """Validate companion metadata without converting malformed values."""
    try:
        value = reader.error_count
    except Exception as exc:
        raise NativeBatchError(f"could not read native error_count: {exc}") from exc
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NativeBatchError("native error_count must be a non-negative integer")
    return value


def stage_native_batches(
    module: ModuleType, cf: ClassifiedFile, prepared: PreparedText,
    writer: ArrowStagingWriter, partitions,
) -> int:
    """Import batch capsules without recreating Python objects for each row."""
    recorded_partition = False
    with native_reader(module, cf, prepared, writer) as reader:
        while (native_batch := reader.next_batch()) is not None:
            try:
                batch = pa.record_batch(native_batch)
                sizes = pa.array(native_batch.encoded_record_sizes)
                writer.write_batch(batch, encoded_record_sizes=sizes)
            except OSError:
                raise
            except Exception as exc:
                # A malformed batch is an implementation/ABI failure, not a
                # rejected source record or a compatibility fallback request.
                raise NativeBatchError(f"invalid native batch for {cf.path}: {exc}") from exc
            if batch.num_rows and not recorded_partition:
                partitions.add({
                    "host": cf.host,
                    "log_type": "iis" if cf.kind == KIND_IIS else guess_web_log_type(cf.path),
                })
                recorded_partition = True
        return read_native_error_count(reader)
