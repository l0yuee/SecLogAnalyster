"""Coverage for two ways `ProgressReporter` could misbehave once
`Case.ingest()` started running both pipelines concurrently against one
shared reporter: a reported phase that moves backwards, and a reporting
callback that takes the ingest down with it.
"""

from __future__ import annotations

import threading

from seclogx.ingest.jobs import (
    PHASE_DONE,
    PHASE_FAILED,
    PHASE_FLATTENING,
    PHASE_SCANNING,
    PHASE_STAGING,
    ProgressReporter,
)


def test_phase_never_moves_backwards():
    """The EVTX pipeline can reach flattening while the aux pipeline is
    still staging; the shared phase must not flip back to the earlier one,
    which reads as the import having regressed."""
    seen: list[str] = []
    r = ProgressReporter(on_update=lambda s: seen.append(s["phase"]))

    r.set_phase(PHASE_STAGING)
    r.set_phase(PHASE_FLATTENING)
    r.set_phase(PHASE_STAGING)  # the slower pipeline, arriving late
    r.set_phase(PHASE_SCANNING)

    assert r.phase == PHASE_FLATTENING
    assert seen[-1] == PHASE_FLATTENING


def test_finish_always_wins_over_phase_ordering():
    """done/failed are terminal and must be reported even though they sit
    outside the pipeline ordering."""
    r = ProgressReporter()
    r.set_phase(PHASE_FLATTENING)
    r.finish()
    assert r.phase == PHASE_DONE

    r2 = ProgressReporter()
    r2.set_phase(PHASE_FLATTENING)
    r2.finish(error="boom")
    assert r2.phase == PHASE_FAILED
    assert r2.error == "boom"


def test_a_failing_callback_never_breaks_the_ingest():
    """Progress reporting is not the work: a full disk while writing the
    job status file, or a display that fails to render, must not abort an
    import that is otherwise succeeding."""

    def explode(_snapshot):
        raise OSError("No space left on device")

    r = ProgressReporter(on_update=explode)

    r.set_phase(PHASE_STAGING)  # forced emit
    r.on_walked(10)
    r.on_scanned(5)
    r.on_table_flattened("syslog", 3)
    r.finish()

    # State is still tracked correctly even though every emit raised.
    assert r.phase == PHASE_DONE
    assert r.files_walked == 10
    assert r.rows_written == {"syslog": 3}


def test_walked_and_scanned_are_reported_separately():
    """Walking and classifying are different counts over different
    denominators -- collapsing them made the reported number jump
    backwards when classification started."""
    snapshots: list[dict] = []
    r = ProgressReporter(on_update=snapshots.append, min_interval=0, min_count_interval=0)

    r.on_walked(2000)
    r.on_scanned(10)

    assert snapshots[-1]["files_walked"] == 2000
    assert snapshots[-1]["files_scanned"] == 10


def test_concurrent_reporting_from_both_pipelines_is_consistent():
    """Both orchestrators call into one reporter from their own threads."""

    class _Staged:
        status = "ok"

    r = ProgressReporter(on_update=lambda s: None)

    def evtx():
        for _ in range(200):
            r.on_evtx_result(_Staged())

    def aux():
        for _ in range(200):
            r.on_aux_result(_Staged())

    threads = [threading.Thread(target=evtx), threading.Thread(target=aux)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert r.evtx_staged == 200
    assert r.aux_staged == 200
    assert r.files_ok == 400
