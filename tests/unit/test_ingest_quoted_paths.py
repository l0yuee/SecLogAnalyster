from pathlib import Path
import shutil

import pytest

from seclogx.case import Case
from seclogx.ingest.resources import IngestOptions

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.mark.parametrize("staging_format", ["ndjson", "arrow"])
@pytest.mark.parametrize("relative,table,expected_rows", [
    ("compact_corpus/valid/syslog.log", "syslog", 16),
    ("evtx/security-seven.evtx", "events", 7),
])
def test_ingest_accepts_apostrophes_in_case_and_source_paths(
    tmp_path, staging_format, relative, table, expected_rows,
):
    source_dir = tmp_path / "analyst's evidence"
    source_dir.mkdir()
    source = source_dir / Path(relative).name
    shutil.copyfile(FIXTURES / relative, source)
    root = tmp_path / "analyst's cases"
    with Case.create("quoted", case_root=root) as case:
        report = case.ingest([str(source)], workers=1,
                             options=IngestOptions(staging_format=staging_format))
        assert report.files_failed == 0 and report.files_partial == 0
        assert report.aux.files_failed == 0 and report.aux.files_partial == 0
        assert case.query(f"SELECT count(*) AS count FROM {table}").iloc[0]["count"] == expected_rows
        assert case.query(f"SELECT DISTINCT source_path FROM {table}")["source_path"].tolist() == [str(source)]
        assert case.info()["catalog"][table]
    with Case.open("quoted", case_root=root) as reopened:
        assert reopened.query(f"SELECT count(*) AS count FROM {table}").iloc[0]["count"] == expected_rows
