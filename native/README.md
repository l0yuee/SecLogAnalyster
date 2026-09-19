# Optional native parsing

`seclogx-native` supplies bounded UTF-8 CLF/Combined and IIS W3C parsers to
`seclogx`. It leaves the public Python, Jupyter, Case and query interfaces in
the main package. Other formats and encodings continue through the Python
parsers. The adapter chooses the backend and owns source verification, staging,
partition metadata and final publication.

The module performs file reading, parsing and Arrow buffer construction while
detached from Python. `next_batch()` returns an object accepted by
`pyarrow.record_batch()`; its `encoded_record_sizes` attribute is accepted by
`pyarrow.array()` and describes the exact original compact JSON record sizes.
No row dictionaries or row callbacks cross the Python boundary. Exported Arrow
buffers are reference counted and outlive both the reader and batch wrappers.
Capsules stay within one process: a file worker for the default staging path,
or the direct conversion coordinator. They never carry buffers between
processes.

The main package also offers
`IngestOptions(parser_backend="auto", direct_parquet=True)` together with
`keep_staging=False` for eligible local sources. This optional path sends the
same batches directly to DuckDB and writes private Parquet files, publishing
each source only after conversion and source verification finish. Staging
remains the default. The companion's parser and batch contract are unchanged.

Normal batches contain at most 16,384 rows and an estimated 16 MiB of Arrow
buffers. A single larger record can occupy a batch by itself, subject to the
existing 32 MiB encoded-record cap and 8 Mi-character physical-line cap. The
physical line splitter follows Python's `str.splitlines()` behavior, strips an
initial UTF-8 BOM and never truncates an oversized line.
Calls also bound the number of scanned lines and decoded input bytes, so a
file containing only invalid lines does not postpone Python signal handling
until EOF. A call may return an empty batch at this boundary; only `None`
means the reader has reached EOF.

The raw string schema remains identical to the existing Arrow staging schema;
the final ingest metadata columns are null until the main conversion stage.
Provenance fields are included in both the batch and encoded-size accounting.
IIS header changes, duplicate header fields, unknown-field JSON, empty fields,
comment lines and ordinary invalid lines preserve the existing parser rules.
Rare date or integer representations that need Python's broader semantics
and IIS headers wider than 4,096 fields raise `UnsupportedInputError`. They must
cause the main adapter to discard all private output for that source before
restarting its Python parser. Disk and
source-integrity errors must never trigger this fallback. A fatal parse error
returns a pending valid prefix first, then raises on the next batch call.

## Building

The companion wheel builds independently of the main setuptools project. Use a
Rust toolchain and the platform C linker (MSVC Build Tools on Windows). The
build uses Python's stable ABI for GIL-enabled CPython 3.10 and newer; it does
not claim support for the distinct free-threaded ABI. This is a build target,
not a statement that every Python/PyArrow/platform combination has been tested.
Build and verify a
platform wheel before distribution; installing that wheel does not require
Rust on the user's machine.

Install directly from this repository when the Rust and C/C++ build toolchains
are available:

```powershell
conda run --no-capture-output -n python314 python -m pip install ./native
```

This is an independent, optional local package. These instructions do not
require or imply that a package has been published on PyPI. Restart existing
Jupyter kernels after installing or replacing the native extension.

From the repository root, in a build environment with maturin installed:

```powershell
conda run --no-capture-output -n python314 python -m maturin build --release --locked --manifest-path native/Cargo.toml --interpreter python
```

The interpreter resolves inside the selected environment. Do not build a debug wheel for performance
measurements. `API_VERSION` identifies the small adapter contract; unsupported
versions must be rejected before any records are staged.

The release profile retains line tables for native stack diagnosis without
changing its optimization level. On MSVC builds the matching PDB is a separate
build artifact under `native/target/release` from the repository root, unless
Cargo's target directory is overridden. Retain it with the exact extension
binary when collecting native profiles. It is not a Python runtime dependency.

`source_handle` is an internal adapter parameter: its owner must keep the
verified file open for the whole reader lifetime, at the initial byte offset.
The reader duplicates that handle and closes only its duplicate. Source
identity and mutation checks remain the responsibility of the main adapter.
