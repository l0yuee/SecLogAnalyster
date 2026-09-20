from __future__ import annotations

import pickle

import duckdb
import pytest

from seclogx.ingest.resources import IngestOptions


@pytest.mark.parametrize("memory_limit", ["", "0GB", "-1GB", "1", "infGB", "NaNGB", "1GB; SELECT 1", None, 1024])
def test_invalid_memory_limits_are_rejected(memory_limit):
    with pytest.raises(ValueError, match="memory_limit"):
        IngestOptions(memory_limit=memory_limit)


@pytest.mark.parametrize("name", ["threads", "staging_chunk_bytes", "flatten_batch_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", None])
def test_resource_counts_must_be_positive_integers(name, value):
    with pytest.raises(ValueError, match=name):
        IngestOptions(**{name: value})


def test_options_survive_worker_serialization_and_apply_to_real_duckdb():
    original = IngestOptions(memory_limit=" 64 mib ", threads=1, staging_chunk_bytes=1024, flatten_batch_bytes=4096)
    options = pickle.loads(pickle.dumps(original))
    assert options == original
    with duckdb.connect() as con:
        options.configure_connection(con)
        assert con.execute("SELECT current_setting('threads')").fetchone() == (1,)
        assert con.execute("SELECT current_setting('preserve_insertion_order')").fetchone() == (False,)
        assert con.execute("SELECT current_setting('memory_limit')").fetchone() == ("64.0 MiB",)
        assert con.execute("SELECT sum(i) FROM range(1000) t(i)").fetchone() == (499500,)
