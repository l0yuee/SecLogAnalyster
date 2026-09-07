"""Coverage for `LocalJobQueue`'s in-process fast path and for the
actionable error it raises in place of a bare `BrokenProcessPool` when a
script calls `Case.ingest()` without an `if __name__ == "__main__":`
guard (worker processes are spawned, so they re-import the caller's
`__main__`).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from seclogx.distributed.queue import LocalJobQueue
from seclogx.errors import UnguardedMainError


def _double(x):
    return x * 2


def _pid_of(_ignored):
    return os.getpid()


def test_single_worker_runs_inline_without_a_process_pool():
    """workers=1 is the documented escape hatch for an unguarded script,
    so it must not need a worker process itself."""
    queue = LocalJobQueue(workers=1)
    results = queue.submit_all(_pid_of, [(1,), (2,), (3,)])
    assert results == [os.getpid()] * 3


def test_single_task_runs_inline_regardless_of_worker_count():
    """Spawning a worker costs more than one small file's parse, so a
    one-task batch stays in this process."""
    queue = LocalJobQueue(workers=8)
    assert queue.submit_all(_pid_of, [(1,)]) == [os.getpid()]


def test_inline_path_still_reports_every_result():
    queue = LocalJobQueue(workers=1)
    seen: list[int] = []
    results = queue.submit_all(_double, [(1,), (2,), (3,)], on_result=seen.append)
    assert sorted(results) == [2, 4, 6]
    assert sorted(seen) == [2, 4, 6]


def test_empty_batch_is_a_no_op():
    assert LocalJobQueue(workers=4).submit_all(_double, []) == []


def _run_script(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    script = tmp_path / "user_script.py"
    script.write_text(textwrap.dedent(body))
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    return subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=180
    )


_SCRIPT_BODY = """
    from pathlib import Path
    from seclogx import Case

    root = Path({tmp!r})
    src = root / "evidence"
    src.mkdir(exist_ok=True)
    for i in range(3):
        (src / f"auth{{i}}.log").write_text(
            "<34>1 2026-01-01T00:00:0%dZ h sshd 1 - - Failed password\\n" % i
        )

    case = Case.create("scripted", case_root=root / "cases")
    report = case.ingest([str(src)]{extra})
    print("ROWS", report.aux.rows_written)
"""


def test_unguarded_script_gets_an_actionable_error_not_brokenprocesspool(tmp_path: Path):
    """Regression test for the trap in the documented Python API: pasting
    the `06_python_api.md` ingest example into a .py file used to die with
    a bare BrokenProcessPool and a traceback pointing at CPython
    internals, saying nothing about the missing __main__ guard."""
    result = _run_script(tmp_path, _SCRIPT_BODY.format(tmp=str(tmp_path), extra=""))

    assert result.returncode != 0
    assert "UnguardedMainError" in result.stderr
    assert '__main__' in result.stderr
    assert "workers=1" in result.stderr
    assert "BrokenProcessPool: A process in the process pool" not in result.stderr.splitlines()[-1]


def test_unguarded_script_works_with_the_workers_1_escape_hatch(tmp_path: Path):
    """The fix the error message offers has to actually work."""
    result = _run_script(tmp_path, _SCRIPT_BODY.format(tmp=str(tmp_path), extra=", workers=1"))

    assert result.returncode == 0, result.stderr
    assert "ROWS {'syslog': 3}" in result.stdout


def test_guarded_script_ingests_in_parallel_normally(tmp_path: Path):
    body = _SCRIPT_BODY.format(tmp=str(tmp_path), extra="")
    guarded = "def main():\n" + textwrap.indent(textwrap.dedent(body), "    ")
    guarded += '\n\nif __name__ == "__main__":\n    main()\n'
    result = _run_script(tmp_path, guarded)

    assert result.returncode == 0, result.stderr
    assert "ROWS {'syslog': 3}" in result.stdout


def test_broken_pool_is_not_misreported_when_main_has_no_file(monkeypatch):
    """A worker that dies for a real reason (OOM kill, segfaulting parser)
    must keep surfacing as BrokenProcessPool -- the guard hint is only
    right when the caller is a script that could be missing the guard."""
    from concurrent.futures.process import BrokenProcessPool

    import seclogx.distributed.queue as queue_mod

    monkeypatch.setattr(queue_mod, "_running_from_unguarded_script", lambda: False)

    class _Exploding(LocalJobQueue):
        def submit_all(self, fn, args_list, on_result=None):
            try:
                raise BrokenProcessPool("worker died")
            except BrokenProcessPool as e:
                hint = queue_mod._unguarded_main_error(fn)
                if hint is None:
                    raise
                raise hint from e

    with pytest.raises(BrokenProcessPool):
        _Exploding(workers=4).submit_all(_double, [(1,), (2,)])
