"""Check an installed wheel outside the checkout with Rust hidden from PATH.

Run from the same Python environment used for product validation. CI also passes
--install to install the wheel and its test extras under the shared constraints.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def without_rust() -> dict[str, str]:
    env = dict(os.environ)
    names = ("cargo", "rustc", "rustup", "cargo.exe", "rustc.exe", "rustup.exe")
    entries = [entry for entry in env.get("PATH", "").split(os.pathsep)
               if entry and not any((Path(entry) / name).is_file() for name in names)]
    env["PATH"] = os.pathsep.join(entries)
    for key in ("CARGO", "RUSTC", "RUSTUP_TOOLCHAIN", "PYTHONPATH"):
        env.pop(key, None)
    env["MATURIN_NO_INSTALL_RUST"] = "1"
    assert shutil.which("cargo", path=env["PATH"]) is None
    assert shutil.which("rustc", path=env["PATH"]) is None
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel_dir", type=Path)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--constraints", type=Path, default=Path("constraints/python314.txt"))
    args = parser.parse_args()
    wheels = sorted(args.wheel_dir.resolve().glob("seclogx-*.whl"))
    if len(wheels) != 1:
        parser.error(f"expected one seclogx wheel, found {len(wheels)}")
    wheel = wheels[0]
    env = without_rust()
    if args.install:
        # Replace even a same-version editable install before the shared suite.
        subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps",
                        str(wheel)], env=env, check=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "--only-binary=:all:",
                        "-c", str(args.constraints.resolve()), f"{wheel}[dev,cluster]"],
                       env=env, check=True)
        subprocess.run([sys.executable, "-m", "pip", "check"], env=env, check=True)

    # Also compare every maintained resource to its wheel copy. This catches
    # accidental sdist/wheel omissions without hard-coding a changing rule count.
    expected_resources = {}
    resource_root = Path(__file__).resolve().parents[1] / "data"
    for subdir in ("attack", "scheduled_tasks", "sigma_rules"):
        for path in (resource_root / subdir).rglob("*"):
            if path.is_file():
                expected_resources[path.relative_to(resource_root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected_resources:
        raise RuntimeError("no source resources found for wheel comparison")
    with zipfile.ZipFile(wheel) as archive:
        actual_resources = {name.removeprefix("seclogx/_bundled_data/"): hashlib.sha256(archive.read(name)).hexdigest()
                            for name in archive.namelist()
                            if name.startswith("seclogx/_bundled_data/") and not name.endswith("/")}
    assert actual_resources == expected_resources

    with tempfile.TemporaryDirectory(prefix="seclogx-wheel-") as temporary:
        work = Path(temporary)
        target = work / "installed"
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index",
                        "--target", str(target), str(wheel)], cwd=work, env=env, check=True)
        probe = r'''
import json, pathlib, shutil, sys
target = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target))
assert shutil.which("cargo") is None
assert shutil.which("rustc") is None
import seclogx
from seclogx import Case, _native
from seclogx.config import BUNDLED_ATTACK_DATA, BUNDLED_SIGMA_RULES_DIR, BUNDLED_SCHEDULED_TASK_BASELINE
from seclogx.detect.rules import load_rules
assert pathlib.Path(seclogx.__file__).resolve().is_relative_to(target)
assert pathlib.Path(_native.__file__).resolve().is_relative_to(target)
assert _native.API_VERSION == 1
for resource in (BUNDLED_ATTACK_DATA, BUNDLED_SIGMA_RULES_DIR, BUNDLED_SCHEDULED_TASK_BASELINE):
    assert resource.resolve().is_relative_to(target)
    assert resource.exists()
assert json.loads(BUNDLED_ATTACK_DATA.read_text(encoding="utf-8"))
assert json.loads(BUNDLED_SCHEDULED_TASK_BASELINE.read_text(encoding="utf-8"))["tasks"]
rules = load_rules(BUNDLED_SIGMA_RULES_DIR)
assert rules.rules
path = pathlib.Path("access.log").resolve()
path.write_text('192.0.2.1 - - [20/Sep/2026:12:34:56 +0000] "GET /wheel HTTP/1.1" 200 10\n', encoding="utf-8")
case = Case.create("wheel", case_root=pathlib.Path("cases"))
report = case.ingest([str(path)], workers=1)
assert report.aux.rows_written == {"web_logs": 1}
assert report.aux.staged_files[0].parser_backend == "native"
with case:
    assert case.query("SELECT uri_stem FROM web_logs")["uri_stem"].tolist() == ["/wheel"]
print(json.dumps({"wheel_native_import": True, "native_ingest": True,
                  "bundled_rules": len(rules.rules), "rust_available": False}))
'''
        subprocess.run([sys.executable, "-I", "-c", probe, str(target)], cwd=work, env=env, check=True)


if __name__ == "__main__":
    main()
