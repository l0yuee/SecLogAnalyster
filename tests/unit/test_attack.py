from __future__ import annotations

from seclogx.attack import lookup_technique, parse_attack_tags


def test_lookup_technique_known_id():
    result = lookup_technique("T1003.001")
    assert result is not None
    assert result["name"] == "LSASS Memory"
    assert result["tactic"] == "Credential Access"


def test_lookup_technique_is_case_insensitive():
    assert lookup_technique("t1003.001") == lookup_technique("T1003.001")


def test_lookup_technique_unknown_id_returns_none():
    assert lookup_technique("T9999.999") is None


def test_parse_attack_tags_extracts_bare_technique_ids():
    tags = ["attack.t1003.001", "attack.credential_access", "attack.execution", "not-an-attack-tag"]
    assert parse_attack_tags(tags) == ["T1003.001"]


def test_parse_attack_tags_multiple_techniques():
    tags = ["attack.T1059.001", "attack.t1003"]
    assert parse_attack_tags(tags) == ["T1059.001", "T1003"]


def test_parse_attack_tags_empty_list():
    assert parse_attack_tags([]) == []


def test_parse_attack_tags_no_technique_tags():
    assert parse_attack_tags(["attack.persistence", "attack.defense_evasion"]) == []
