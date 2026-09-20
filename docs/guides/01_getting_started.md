# 1. Getting started

**Language: English | [中文](01_getting_started.zh-CN.md)**

**[Guide index](../index.md)** -- 01. Getting started | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | [10. Distributed deployment](10_distributed_deployment.md)

---

## What seclogx is for

Forensic acquisitions produce Windows Event Log (`.evtx`) files that are
painful to work with directly: a binary format, verbose XML once
extracted, and wildly inconsistent fields across the hundreds of
providers that write to it. Pushing them into a SIEM like ELK for
one-off case analysis is often worse -- brittle index mappings silently
drop fields you needed.

seclogx exists to make the first hours of triage fast:

- Point it at one or more forensic acquisition directories (they don't
  need to be under one parent folder, and can come from different
  hosts).
- It parses **every** `.evtx` channel generically -- Security, System,
  Application, Sysmon Operational, PowerShell Operational,
  WMI-Activity, and anything else -- into one normalized, queryable
  table.
- It also discovers and normalizes, in the same pass: on-disk **Scheduled
  Task** definitions (a persistence artifact), **IIS/nginx/Apache/Tomcat**
  access logs *and* error/diagnostic logs (both major log categories a
  web application produces, including IIS HTTP.sys/HTTPERR),
  **Exchange** CSV logs (Message Tracking gets first-class columns;
  other recognized Exchange CSV types retain their fields in a generic table),
  **Linux** syslog (BSD/RFC-3164 and RFC 5424 -- `auth.log`/`secure`
  content included), the Linux Audit Framework (auditd), and systemd
  journal export logs, **database** logs (MySQL/MariaDB error/
  general/slow query logs, PostgreSQL, MSSQL, Oracle alert log), **Tencent
  Cloud Host Security** client text logs (YDService, HIDS/YDLive, scanners,
  YDFlame/YDUtils/YDQuaraV2, YDEyes), and **Windows Registry** hives (SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT,
  per-user NTUSER.DAT/UsrClass.dat). EVTX discovery uses the `.evtx` suffix;
  auxiliary candidates are classified from a bounded content prefix, with
  suffix exclusions and some format-specific filename/path hints. Renaming
  evidence can therefore affect detection. See
  [02. Log types & schema](02_log_types_and_schema.md) for the full
  twelve-table picture.
- You get DataFrames and chunk iterators through a Python `Case` object,
  plus CLI previews/CSV export and built-in
  Sigma-rule threat hunting with MITRE ATT&CK tagging, covering both
  Windows Event Log and web access logs. **No SQL required either**:
  `seclogx search` / `Case.search()` filter any table with plain
  field/value conditions -- exact, fuzzy, or regex matching.
- Reconciliation reports identify discovered files that parsed partially,
  failed, or could not be classified; unsupported rules are also reported.
  Known unrelated suffixes and empty auxiliary files are filtered, and
  inaccessible paths may be skipped. This is not a complete acquisition inventory.
- **Chunked access for large log tables.** Log-table accessors, SQL queries,
  search and timelines offer streaming alternatives; `search()` estimates
  result size before fetching. Ordinary DataFrame methods and derived analyses
  can still exhaust memory. Consume chunks one at a time rather than retaining
  all of them (see [03. Querying & search](03_querying_and_search.md)
  and [08. Performance & scale](08_performance_and_scale.md)).

It's designed for one workstation by default, with no external services
required. Import time and disk/memory requirements depend on the log formats,
record widths, parallelism and storage. Chunked delivery avoids materializing
the whole query result but does not bound every operation's memory. An opt-in, purely
environment-variable-activated distributed mode also exists for large
ingest batches, large Sigma rule sets, or multiple analysts sharing one
case concurrently -- see
[10. Distributed deployment](10_distributed_deployment.md); it doesn't
change anything described above unless you turn it on.

## Install

The package includes its Rust parser: one normal installation provides the
Python API and the native extension. Analysts do not install an accelerator
separately or choose performance modes for each import. Choose a matching
precompiled wheel when available; source installation requires the build tools
listed below.

### Install a precompiled wheel

Open a successful [Product tests and wheels workflow run](https://github.com/l0yuee/SecLogAnalyster/actions/workflows/ci.yml)
for the version you intend to use. Download and extract `wheels-windows-x64`,
`wheels-linux-x64`, `wheels-macos-arm64`, or `wheels-macos-x64` as appropriate.
Artifacts may require a GitHub sign-in and expire; if the needed artifact is
unavailable, use the source instructions below. Workflow artifacts are not
package-index or GitHub Release publications.

In `python314`, install the extracted wheel by its actual filename. For example,
on Windows x64:

```console
conda activate python314
python -m pip install --only-binary=:all: ./seclogx-0.2.0-cp310-abi3-win_amd64.whl
python -m pip install jupyterlab ipykernel
python -m ipykernel install --user --name python314 --display-name "Python (python314)"
python -m jupyterlab
```

Create the environment first if needed: `conda create -n python314 python=3.14.2 pip`.
The matching wheel includes the Rust extension and rules. **The analyst does not
need Rust, Cargo, maturin, or a C/C++ compiler for this installation.** Pip installs
runtime dependencies; `--only-binary=:all:` fails clearly if a dependency wheel is
missing instead of starting a source build. Linux wheels require glibc 2.28 or
newer; use the correct OS and CPU architecture. Platform runtime libraries, such
as the Windows Visual C++ Redistributable mentioned below, may still be needed.

### Prepare the machine once

Use Git to obtain the repository and an installed conda distribution for the
project environment. The Python package requires Python 3.10 or newer; this
project uses GIL-enabled CPython 3.14 in **`python314`**, isolated from `base`.

For a source installation, install **stable Rust including Cargo**, plus your
platform's native compiler/linker:

| Platform | Tools to install before `pip install` |
| --- | --- |
| Windows | Install Visual Studio Build Tools with **Desktop development with C++**, including the MSVC x64/x86 tools and a Windows SDK. Then run the Windows installer from [Rust installation](https://rust-lang.org/tools/install/) and use the stable MSVC toolchain. See the [official MSVC prerequisites](https://rust-lang.github.io/rustup/installation/windows-msvc.html). |
| Ubuntu/Debian | Install the compiler tools with `sudo apt-get update` and `sudo apt-get install build-essential curl`. Install stable Rust with the [official rustup instructions](https://doc.rust-lang.org/book/ch01-01-installation.html). Other Linux distributions need their equivalent GCC or Clang and linker packages. |
| macOS | Run `xcode-select --install` for Apple's command-line compiler tools, then install stable Rust with the [official rustup instructions](https://doc.rust-lang.org/book/ch01-01-installation.html). |

On Linux/macOS, the official rustup installation command is:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Cargo is included with Rust; no separate Cargo installation is needed. Open a
new terminal after installation, then check `rustc --version` and
`cargo --version`. A working Rust/linker toolchain is required for a successful
source build. If Cargo is missing, the build backend may try to acquire a
temporary Rust toolchain; preparing tools explicitly avoids depending on that
network step. A failed native build does not silently produce a Python-only
package.

Python dependencies, including DuckDB, PyArrow, pandas, EVTX and registry
libraries, are installed by pip. With matching dependency wheels, **do not
install a separate DuckDB server, Arrow C++ library, or EVTX executable**.
[PyArrow wheels include Arrow/Parquet C++ libraries](https://arrow.apache.org/docs/python/install.html);
[DuckDB runs inside Python](https://duckdb.org/docs/stable/clients/python/overview).
If pip cannot find a dependency wheel for your Python/platform combination,
building that dependency from source can require additional tools; use a
supported wheel combination or follow that dependency's own build instructions.
Local analysis needs no Redis, S3 service or container runtime.

On Windows, a missing DLL when importing a dependency may require the
[Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
This is a runtime library, separate from the compiler tools; the
[PyArrow installation notes](https://arrow.apache.org/docs/python/install.html)
describe this case.

### Install the project and Notebook environment

In a terminal, clone the repository if it is not already present:

```bash
git clone https://github.com/l0yuee/SecLogAnalyster.git
cd SecLogAnalyster
```

If `python314` does not exist yet, create it once with
`conda create -n python314 python=3.14.2 pip`; reuse the existing environment
otherwise. Then run from the repository root:

```bash
conda activate python314
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install jupyterlab ipykernel
python -m ipykernel install --user --name python314 --display-name "Python (python314)"
seclogx version
seclogx --help
python -m jupyterlab
```

The project build backend is installed automatically by pip and compiles the
extension with release optimizations; neither a separate maturin command nor
`pip install ./native` is needed. The first source build downloads Rust crates
and Python dependencies and can take time. `pip install .` also builds and
installs the extension; editable installation is convenient when working from
this checkout. Normal wheels include the bundled rules and reference data; an
editable installation uses the checkout, which must remain available.

Choose **Python (python314)** in Jupyter and check the interpreter in a cell:

```python
import sys
print(sys.executable)
```

Starting JupyterLab in an environment does not switch an already-running
kernel. Use `conda run --no-capture-output -n python314 python ...` for scripts
when activation is unavailable. CLI-only use does not require JupyterLab or
ipykernel.

### Upgrade or deploy a built wheel

After updating the checkout, run `python -m pip install -e .` again in
`python314` to rebuild the extension, then **restart existing Jupyter kernels**.
Editable installation reflects Python edits, but does not rebuild changed Rust
code until this install/build step runs. Close active import jobs before an
upgrade.

A deployment maintainer can build a matching platform wheel with
`python -m pip wheel --no-deps . --wheel-dir dist`. Installing that completed
wheel does not compile this project's Rust code, so the analyst machine does
not need Rust or a C/C++ compiler for seclogx itself. Dependency wheel
availability and platform runtime libraries still apply. See the
[native component build notes](../../native/README.md) for ABI and platform
boundaries.

## The case workspace

A **case** is a named workspace under `./cases/<name>/`. Case management commands
use `--dir`; ingest and analysis commands use `--case-root`.

```text
cases/<name>/
  case.json                   # atomic committed catalog, source ledger, ingest history
  .ingest/<transaction_id>/
    state.json                # batch state and process identity
    report.json               # detailed per-source outcomes
    s_evtx/                   # EVTX temporary shards
    s_aux/                    # auxiliary temporary shards; direct sources skip these
    lake/<table>/.../*.parquet # immutable output, visible only when committed
    logs/                     # batch reconciliation logs
    workers/                  # active worker identities protect cleanup
  .readers/                   # leases protecting open query snapshots
  jobs/<job_id>.json          # progress, process identity and heartbeat
  jobs/<job_id>.log           # background stdout/stderr and reports
  hunts/<run>/               # complete saved hunt matches and summary
  lake/                      # older case layouts remain readable
```

Tables retain their format-specific Hive partitions; see [schemas](02_log_types_and_schema.md).
With S3 configured, Parquet objects live in object storage; metadata, staging,
worker/reader coordination and job files still require the shared case directory.
See [distributed deployment](10_distributed_deployment.md).

An ingest writes into a private batch workspace. One atomic catalog replacement
publishes its Parquet files, source ledger and run history together. An aborted
batch never becomes a partial query result. `partial` source outcomes can still
be committed: inspect the report to distinguish recovered data from complete
sources. Query connections retain the committed snapshot captured when opened;
reopen an existing Case after a background import to see its new commit.

Retrying an unchanged source already committed with the same path, host, format,
EVTX decoding/raw settings and ingest contract skips it and reports
`already_imported`. Different hosts are kept distinct. A changed file or different
source identity is a separate import; this is not row-level duplicate removal.
An unsuccessful batch restarts from its sources on retry, not a saved byte offset.
Do not manually delete committed `.ingest` directories: the catalog can reference
their files even though the directory name starts with a dot.

Compatible local Web/IIS sources automatically use native direct output. Other
inputs stage before conversion; `auto` selects Arrow IPC/ZSTD for supported
staging paths at 16 MiB or above, gzip NDJSON below that threshold. EVTX also
supports Arrow staging, and final Parquet uses ZSTD level 1. Temporary shards are
removed after successful conversion unless `keep_staging=True`; source evidence
is never deleted. Retaining staging supports diagnosis, not offset-based resume.

Background jobs have an independent heartbeat and use PID plus creation time to
identify processes. `c.cancel_job(job_id)` stops owned local processes and workers.
`c.cleanup_ingest()` removes inactive uncommitted outputs, safely retired files,
and terminal job logs older than seven days, keeping status and audit JSON.
The next ingest also cleans inactive uncommitted work. An active worker prevents
cleanup even after its coordinator dies. Cross-host process cancellation must be
performed on the originating host.

Small local Parquet files are merged automatically after committed imports when
enough accumulate in one partition. `c.compact()` or `seclogx compact <case>` can
request maintenance sooner. Open readers keep their old snapshot; retired files
are reclaimed only after their reader leases end. Compaction does not currently
support S3 storage.

### Reproduce the product tests

CI uses CPython 3.14.2 and the same committed product suite on Windows x64, Linux
x64 and macOS arm64/x64. The runtime pins DuckDB 1.5.5 and EVTX 0.12.1 to the
versions used for SQL isolation and recovery validation. Shared constraints pin
the remaining validation dependencies. With source build tools prepared:

```console
conda activate python314
python -m pip install -c constraints/python314.txt -e ".[dev,cluster]"
python -m pytest
```

Small synthetic fixtures and generated failure cases are committed together
with the tests; [testing instructions](../../tests/README.md) explain collection
and wheel verification. These tests do not establish large-volume performance.

## Quickstart

```bash
seclogx case init incident42
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx sources incident42
seclogx fields incident42 events
seclogx search incident42 events --contains Image=mimikatz --eq host=WKS01
seclogx hunt incident42
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

Where to go next:

- **[02. Log types & schema](02_log_types_and_schema.md)** -- what each of
  the twelve tables holds and what to look for in it.
- **[03. Querying & search](03_querying_and_search.md)** -- SQL, the
  no-SQL `search()` interface, and bounded-memory delivery.
- **[04. Threat hunting](04_threat_hunting.md)** -- Sigma rules and ATT&CK
  tagging.
- **[05. CLI reference](05_cli_reference.md)** / **[06. Python API](06_python_api.md)**
  -- the full command/method reference.
- **[07. Recipes](07_recipes.md)** -- copy-pasteable starting points.

## License and rule attribution

seclogx's own code is MIT licensed (`LICENSE`). The bundled Sigma rules
under `data/sigma_rules/` are copied unmodified from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the Detection
Rule License 1.1 (`data/sigma_rules/LICENSE-DRL-1.1.txt`); exact
upstream source and commit per rule is recorded in
`data/sigma_rules/SOURCES.md`, and every match reports the original
rule's authorship. See the repo root `README.md` for the full license
text and pointers.
