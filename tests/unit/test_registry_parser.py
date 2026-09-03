from __future__ import annotations

from pathlib import Path

from registry_hive_builder import build_hive

from seclogx.ingest.logsources.parsers.registry import parse_registry_hive_file


def _write_hive(tmp_path: Path, embedded_name: str, filename: str) -> Path:
    p = tmp_path / filename
    p.write_bytes(build_hive(embedded_name))
    return p


def test_parse_registry_hive_software_shaped(tmp_path: Path):
    p = _write_hive(tmp_path, "\\System32\\Config\\SOFTWARE", "SOFTWARE")
    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    assert err == 0
    # root(1) + CurrentVersion(1 key-only) + Run(2 values) + Services(1
    # key-only) + TestSvc(1) + Plain(1) + Empty(1 key-only)
    assert ok == 8
    assert len(rows) == 8

    by_path = {(r["key_path"], r["value_name"]): r for r in rows}

    root_row = by_path[("\\", None)]
    assert root_row["hive_type"] == "software"
    assert root_row["hive_root"] == "HKEY_LOCAL_MACHINE\\SOFTWARE"
    assert root_row["full_path"] == "HKEY_LOCAL_MACHINE\\SOFTWARE"
    assert root_row["value_type"] is None

    updater = by_path[("\\CurrentVersion\\Run", "Updater")]
    assert updater["value_type"] == "REG_SZ"
    assert updater["value_text"] == "C:\\Windows\\System32\\update.exe"
    assert updater["full_path"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\CurrentVersion\\Run"

    payload = by_path[("\\CurrentVersion\\Run", "Payload")]
    assert payload["value_type"] == "REG_BINARY"
    assert payload["value_size"] == 200
    assert payload["entropy"] > 7.0  # deliberately high-entropy synthetic payload

    plain = by_path[("\\Plain", "Data")]
    assert plain["value_type"] == "REG_BINARY"
    assert plain["value_size"] == 40
    assert plain["entropy"] < 1.0  # all-identical bytes, deliberately low-entropy

    empty = by_path[("\\Empty", None)]
    assert empty["value_name"] is None
    assert empty["value_type"] is None

    assert all(r["transaction_log_applied"] is False for r in rows)


def test_parse_registry_hive_ntuser_shaped_derives_user_root(tmp_path: Path):
    evidence_root = tmp_path / "evidence" / "Users" / "alice"
    evidence_root.mkdir(parents=True)
    p = _write_hive(evidence_root, "\\Users\\alice\\NTUSER.DAT", "NTUSER.DAT")

    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    assert err == 0
    assert rows[0]["hive_type"] == "ntuser"
    assert rows[0]["hive_root"] == "HKEY_USERS\\alice"


def test_parse_registry_hive_default_hive_type(tmp_path: Path):
    p = _write_hive(tmp_path, "\\System32\\Config\\DEFAULT", "DEFAULT")

    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    assert rows[0]["hive_type"] == "default"
    assert rows[0]["hive_root"] == "HKEY_USERS\\.DEFAULT"


def test_parse_registry_hive_unidentified_falls_back_to_unknown(tmp_path: Path):
    p = _write_hive(tmp_path, "SOMETHING_WEIRD", "weird.hive")

    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    assert rows[0]["hive_type"] == "unknown"
    assert rows[0]["hive_root"] == "UNKNOWN\\SOMETHING_WEIRD"


def test_parse_registry_hive_falls_back_when_transaction_log_recovery_fails(tmp_path: Path):
    p = _write_hive(tmp_path, "\\System32\\Config\\SOFTWARE", "SOFTWARE")
    (tmp_path / "SOFTWARE.LOG1").write_bytes(b"not a real transaction log")

    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    # recovery failed, but the hive itself still parses fine from the raw file
    assert err == 0
    assert ok == 8
    assert all(r["transaction_log_applied"] is False for r in rows)


def test_parse_registry_hive_with_no_transaction_log_present(tmp_path: Path):
    p = _write_hive(tmp_path, "\\System32\\Config\\SOFTWARE", "SOFTWARE")

    rows, ok, err = parse_registry_hive_file(p, host="LAB01")

    assert all(r["transaction_log_applied"] is False for r in rows)
