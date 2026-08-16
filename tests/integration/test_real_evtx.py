"""End-to-end ingest against real .evtx samples.

Not run by default -- point SECLOGX_TEST_EVTX_DIR at a local checkout of
github.com/sbousseaden/EVTX-ATTACK-SAMPLES (or any directory of real
.evtx files) to exercise this.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from seclogx.case import Case

EVTX_DIR = os.environ.get("SECLOGX_TEST_EVTX_DIR")

pytestmark = pytest.mark.skipif(not EVTX_DIR, reason="set SECLOGX_TEST_EVTX_DIR to run against real .evtx samples")


def test_ingest_real_evtx_directory(tmp_path: Path):
    case = Case.create("real", case_root=tmp_path / "cases")
    report = case.ingest([f"{EVTX_DIR}:REALHOST"])

    assert report.files_discovered > 0
    assert report.records_flattened > 0
    # every file should be accounted for as ok, partial, or failed -- never lost
    assert report.files_ok + report.files_partial + report.files_failed == report.files_discovered

    df = case.summary()
    assert not df.empty
