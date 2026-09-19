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
separately or choose performance modes for each import. This repository
currently documents a **source installation**, which requires the build tools
below. It does not assume a published, ready-to-download seclogx wheel.

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
`conda create -n python314 python=3.14 pip`; reuse the existing environment
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

Everything revolves around a **case** -- a named workspace under
`./cases/<name>/` (`case init/list/info` use `--dir`; ingest/query commands use
`--case-root`) that holds:

```
cases/<name>/
  case.json                         # hosts and ingest run history
  staging/<batch_id>/<host>/*.ndjson.gz       # EVTX temporary shards (removed after successful conversion)
  staging_aux/<batch_id>/<host>/*.{ndjson.gz,arrow}  # auxiliary temporary shards (direct sources skip these)
  logs/ingest_<batch_id>.log          # EVTX reconciliation report
  jobs/<job_id>.json                 # background status snapshot
  jobs/<job_id>.log                  # background stdout/stderr and reports
  lake/
    events/host=<h>/channel=<c>/*.parquet                       # Windows Event Log
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat access logs
    web_error_logs/host=<h>/log_type=<t>/*.parquet               # nginx/Apache/Tomcat/IIS HTTPERR error logs
    scheduled_tasks/host=<h>/*.parquet                           # Task Scheduler definitions
    exchange_message_tracking/host=<h>/*.parquet                 # Exchange mail flow
    exchange_logs/host=<h>/log_type=<t>/*.parquet                # other Exchange CSV logs
    syslog/host=<h>/*.parquet                                    # generic syslog, incl. auth.log/secure
    auditd_logs/host=<h>/record_type=<r>/*.parquet                # Linux Audit Framework
    journal_logs/host=<h>/*.parquet                              # systemd journal export
    db_logs/host=<h>/log_type=<t>/*.parquet                       # MySQL/PostgreSQL/MSSQL/Oracle logs
    qcloud_logs/host=<h>/log_type=<t>/*.parquet                   # Tencent Cloud Host Security client logs
    registry/host=<h>/hive_type=<t>/*.parquet                     # Windows Registry hives
```

`lake/` can live on S3-compatible object storage instead of local disk
(`SECLOGX_STORAGE_BACKEND=s3` -- opt-in, see
[10. Distributed deployment](10_distributed_deployment.md)); `case.json`,
`staging/`, `staging_aux/`, `logs/`, and `jobs/` always stay local/NFS, in every
mode.

You create a case once (`seclogx case init`), then `ingest` into it as
many times as you like -- from different source paths, different hosts,
even weeks apart. Every ingest run is additive and recorded in
`case.json`. A single `ingest` run discovers and ingests every supported
format found under the source paths in one pass -- you don't ingest each
log type separately. A case only exposes the tables it actually has data
for; check with `seclogx sources <case>` / `Case.table_counts()`.

Imports are additive, without cross-run deduplication or checkpoint/resume.
Overlapping source paths are deduplicated within one scan, but running the same
import twice appends duplicate rows. Compatible local Web/IIS sources use native
direct output automatically; other sources stage before conversion. Temporary
shards are removed after successful conversion by default. `keep_staging=True`
retains them for diagnosis and selects the staged path, without affecting source
evidence. Retained staging is not a resumable checkpoint, and cleanup does not
eliminate peak staging disk use. Background ingest does not
guarantee consistent queries while files are still being written. Wait for
completion, review the report and reopen the Case before analysis.

For sources that need staging, `auto` selects Arrow IPC for files of at least 16 MiB
with ZSTD level 1, smaller files use gzip NDJSON. EVTX always uses NDJSON.
Auxiliary Parquet uses ZSTD level 1. Advanced diagnostic overrides,
memory/thread budgets and batch sizes are documented in the
[CLI reference](05_cli_reference.md) and [Notebook API](06_python_api.md).

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
