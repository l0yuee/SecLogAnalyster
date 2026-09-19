# Native parsing and build notes

The main `seclogx` installation includes bounded Rust UTF-8 CLF/Combined
and IIS W3C parsers as `seclogx._native`. It leaves the public Python, Jupyter, Case and query interfaces in
the main package. Other formats and encodings continue through the Python
parsers. The adapter chooses the backend and owns source verification, staging,
partition metadata and final publication.

The module performs file reading, parsing and Arrow buffer construction while
detached from Python. `next_batch()` returns an object accepted by
`pyarrow.record_batch()`; its `encoded_record_sizes` attribute is accepted by
`pyarrow.array()` and describes the exact original compact JSON record sizes.
No row dictionaries or row callbacks cross the Python boundary. Exported Arrow
buffers are reference counted and outlive both the reader and batch wrappers.
Capsules stay within one process: a file worker for the staged path,
or the direct conversion coordinator. They never carry buffers between
processes.

Normal `Case.ingest(sources)` and `ingest_background(sources)` calls automatically
use native Arrow-to-DuckDB conversion for compatible local sources and publish
private Parquet after conversion and source checks finish. Other inputs and
execution contexts use the staged compatibility path. `parser_backend="auto"`,
`direct_parquet=None` and `keep_staging=False` are defaults; advanced overrides
remain for diagnostics. No accelerator installation or per-import switch is
required. The parser and batch contract are the same on staged and direct paths.

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

## Installation and building

Follow the complete installation instructions in the [English guide](../docs/guides/01_getting_started.md#install)
or [中文指南](../docs/guides/01_getting_started.zh-CN.md#安装). Source installation
needs stable Rust/Cargo and a platform C/C++ compiler/linker: Visual Studio
Build Tools with MSVC and Windows SDK on Windows, GCC or Clang on Linux, and
Xcode command-line tools on macOS. Pip installs the maturin build backend.

Run from the repository root:

```powershell
conda run --no-capture-output -n python314 python -m pip install -e .
```

This builds the release extension and installs it with the Python package.
`pip install .` does the same for a regular installation. Rules and reference
data are included in normal wheels. No separate `pip install ./native` is
needed. The old standalone `seclogx-native` build remains a developer compatibility
target; the main adapter prefers its bundled extension.

The build targets Python's stable ABI for GIL-enabled CPython 3.10 and newer,
not the distinct free-threaded ABI. This is a build target, not a claim that
every Python/PyArrow/platform combination has been tested. Existing Jupyter
kernels must restart after installing or replacing the extension.

To build a deployable platform wheel from the repository root:

```powershell
conda run --no-capture-output -n python314 python -m pip wheel --no-deps . --wheel-dir dist
```

An analyst installing the completed matching wheel does not need Rust/C++
build tools for seclogx itself. Dependency wheels and platform runtime libraries
still need to be available. These instructions do not imply a public wheel has
already been published. Without Cargo, maturin may acquire a temporary Rust
toolchain during the build; setting `MATURIN_NO_INSTALL_RUST=1` disables that
acquisition. An offline source build needs a prepared Rust/compiler toolchain,
Python build/runtime dependencies and Cargo's cached crates. There is no runtime
compiler or accelerator download, and native build failures do not silently
install a Python-only package.

For extension development with maturin already installed, the root build is:

```powershell
conda run --no-capture-output -n python314 python -m maturin build --release --locked --interpreter python
```

The interpreter resolves inside the selected environment. Rust source changes
need a new build/install, including with editable installation. Do not use a
debug wheel to assess release performance. `API_VERSION` identifies the adapter
contract; unsupported versions must be rejected before records are staged.

The release profile retains line tables for native stack diagnosis without
changing its optimization level. On MSVC builds the matching PDB is a separate
build artifact under `native/target/release` from the repository root, unless
Cargo's target directory is overridden. Retain it with the exact extension
binary when collecting native profiles. It is not a Python runtime dependency.

`source_handle` is an internal adapter parameter: its owner must keep the
verified file open for the whole reader lifetime, at the initial byte offset.
The reader duplicates that handle and closes only its duplicate. Source
identity and mutation checks remain the responsibility of the main adapter.
