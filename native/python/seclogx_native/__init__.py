"""Optional native parser implementation; the public Case API stays in seclogx."""

from ._native import API_VERSION, NativeWebReader, UnsupportedInputError, __version__


def open_web_file(path, kind, host, log_type, source_path, source_file, file_sha256,
                  schema_columns, **limits):
    """Open a bounded reader; consume batches in this same worker process."""
    return NativeWebReader(str(path), kind, host, log_type, source_path, source_file,
                           file_sha256, schema_columns, **limits)


__all__ = ["API_VERSION", "NativeWebReader", "UnsupportedInputError", "__version__", "open_web_file"]
