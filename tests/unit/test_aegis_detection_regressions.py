"""Format detection must agree with parsing and preserve other log families."""
from pathlib import Path

import pytest

from seclogx.ingest.logsources.discovery import ClassifiedFile
from seclogx.ingest.logsources.sniff import classify_file
from seclogx.ingest.logsources.stage import stage_aux_file
from seclogx.ingest.resources import IngestOptions


def _source(tmp_path: Path, content: bytes, name: str = "input.log") -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("staging_format", ["ndjson", "arrow"])
def test_bomless_utf16_detection_and_staging_agree(tmp_path, encoding, staging_format):
    text = "2026-01-02 03:04:05 [INFO] synthetic\n"
    path = _source(tmp_path, text.encode(encoding), "AliSecCheck/data/detect/log/data.4")
    kind = classify_file(path)
    assert kind == "aegis_core"
    manifest = stage_aux_file(
        ClassifiedFile(path, "SYNTHETIC", path.stat().st_size, kind),
        tmp_path / "staging",
        IngestOptions(staging_format=staging_format),
    )
    assert (manifest.status, manifest.record_count, manifest.error_count) == ("ok", 1, 0)


def test_mz_hostname_is_not_a_pe_executable(tmp_path):
    path = _source(tmp_path, b'MZ.example - - [02/Jan/2026:03:04:05 +0000] "GET / HTTP/1.1" 200 10\n')
    assert classify_file(path) == "web_access"


@pytest.mark.parametrize("prefix,kind", [
    (b"Jan  2 03:04:05 host service: reading /usr/local/aegis/ logs\n", "syslog"),
    (b"# Time: 2026-01-02T03:04:05.000000Z\n# Query_time: 1.0 Lock_time: 0.0 Rows_sent: 1 Rows_examined: 1\n", "mysql_slow"),
    (b'#Software: Microsoft Internet Information Services 10.0\n#Fields: date time s-ip cs-method cs-uri-stem c-ip sc-status\n', "iis"),
])
def test_aegis_text_cannot_override_an_established_log_family(tmp_path, prefix, kind):
    path = _source(tmp_path, prefix + b"2026-01-02 03:04:05 [INFO] /usr/local/aegis/ quoted diagnostic\n")
    assert classify_file(path) == kind


def test_orphan_prefix_does_not_hide_aegis(tmp_path):
    path = _source(tmp_path, b"orphan line\n2026-01-02 03:04:05 [INFO] /usr/local/aegis/ synthetic\n")
    assert classify_file(path) == "aegis_core"


def test_aegis_first_record_wins_over_generic_mssql_shape(tmp_path):
    path = _source(
        tmp_path, b"2026-01-02 03:04:05.12 [INFO]  synthetic\n",
        "AliSecCheck/data/detect/log/data.4",
    )
    assert classify_file(path) == "aegis_core"


def test_relocated_aegis_first_record_can_use_later_product_context(tmp_path):
    path = _source(tmp_path, b"2026-01-02 03:04:05.12 [INFO]  starting\n"
                   b"2026-01-02 03:04:06 [INFO] /usr/local/aegis/ synthetic\n")
    assert classify_file(path) == "aegis_core"


@pytest.mark.parametrize("prefix", [
    b"MZ\x90\x00",
    b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00",
    b"\x7fELF\x02\x01",
])
def test_binary_headers_with_embedded_aegis_text_stay_unknown(tmp_path, prefix):
    path = _source(tmp_path, prefix + b"\n2026-01-02 03:04:05 [INFO] /usr/local/aegis/ synthetic\n")
    assert classify_file(path) is None
