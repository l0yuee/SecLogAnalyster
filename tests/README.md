Product validation uses the committed tests and fixtures on every platform.
Use CPython 3.14.2 with the shared dependency constraints for the same dependency
versions as CI. Source installation builds the bundled Rust extension and needs
the platform compiler toolchain described in the installation guide.

```console
conda activate python314
python -m pip install -c constraints/python314.txt -e ".[dev,cluster]"
python -m pytest
```

CI builds a wheel and runs this same suite against the installed wheel on Windows
x64, Linux x64, and macOS arm64/x64. Native parser tests import the bundled
extension directly so a missing extension cannot turn the suite green by skipping
its native coverage. Optional external EVTX-directory tests and genuinely
unavailable operating-system capabilities have explicit skip reasons.

The [compact corpus](fixtures/compact_corpus/README.md) contains small synthetic
source samples with byte-level hashes and expected classifications and counts.
Other fixtures cover additional formats; unit tests construct malformed input,
encoding boundaries and failure scenarios as needed. These tests make no
large-volume throughput or peak-memory guarantee.

The default pytest configuration excludes developer-only measurement helper
tests. An explicit invocation with `-o addopts=` can run such a helper locally;
those files are not part of the product suite.

To check a built wheel outside the checkout while hiding Rust from the child
process environment, run:

```console
python scripts/check_wheel.py dist
```

CI additionally uses `--install --constraints constraints/python314.txt` to
install the wheel and test dependencies. Validated wheels and the source
distribution are retained as workflow artifacts. Building an artifact does not
publish it to a package index or a GitHub Release.

On macOS Intel, CI first builds the pinned `cryptography` dependency required by
the Moto test helper, using Rust and Homebrew OpenSSL. Upstream no longer ships
Intel macOS wheels for its current versions. This test-only prerequisite keeps
the same dependency version across platforms; ordinary analyst installation
does not require Moto or `cryptography`. The subsequent seclogx wheel installation
and native ingest probe still run with Rust hidden. See the upstream
[platform change](https://cryptography.io/en/latest/changelog/#v49-0-0) and
[macOS build instructions](https://cryptography.io/en/latest/installation/#building-cryptography-on-macos).
