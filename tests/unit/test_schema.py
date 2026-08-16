from __future__ import annotations

from seclogx.ingest.flatten import flatten_case  # noqa: F401 (import sanity)
from seclogx.schema import CORE_COLUMNS, COLUMN_NAMES, EXTRACTION_SQL, PROVENANCE_COLUMNS

# Columns supplied by flatten.py's provenance join/constants override, not EXTRACTION_SQL.
FLATTEN_OVERRIDES = set(PROVENANCE_COLUMNS) | {"ingest_batch_id", "ingested_at", "raw_xml"}


def test_every_column_is_either_extracted_or_overridden():
    covered = set(EXTRACTION_SQL) | FLATTEN_OVERRIDES
    missing = set(COLUMN_NAMES) - covered
    assert not missing, f"columns with neither an EXTRACTION_SQL entry nor a flatten.py override: {missing}"


def test_no_duplicate_column_names():
    assert len(COLUMN_NAMES) == len(set(COLUMN_NAMES))


def test_core_columns_match_column_names():
    assert COLUMN_NAMES == [c[0] for c in CORE_COLUMNS]
