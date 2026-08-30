from __future__ import annotations

from pathlib import Path

import pandas as pd

from seclogx.csvutil import export_chunks_to_csv


def test_export_chunks_to_csv_writes_single_header_and_all_rows(tmp_path: Path):
    chunks = [
        pd.DataFrame({"a": [1, 2], "b": ["x", "y"]}),
        pd.DataFrame({"a": [3], "b": ["z"]}),
        pd.DataFrame({"a": [4, 5], "b": ["w", "v"]}),
    ]
    out = tmp_path / "out.csv"

    total = export_chunks_to_csv(iter(chunks), out)

    assert total == 5
    lines = out.read_text().splitlines()
    assert lines[0] == "a,b"  # header written exactly once
    assert len(lines) == 1 + 5  # header + one line per row
    assert lines[1:] == ["1,x", "2,y", "3,z", "4,w", "5,v"]


def test_export_chunks_to_csv_empty_iterator_still_creates_file(tmp_path: Path):
    out = tmp_path / "empty.csv"

    total = export_chunks_to_csv(iter([]), out)

    assert total == 0
    assert out.exists()
    assert out.read_text() == ""


def test_export_chunks_to_csv_single_chunk(tmp_path: Path):
    out = tmp_path / "single.csv"
    total = export_chunks_to_csv(iter([pd.DataFrame({"n": [1, 2, 3]})]), out)
    assert total == 3
    assert out.read_text().splitlines() == ["n", "1", "2", "3"]
