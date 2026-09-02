from __future__ import annotations

from pathlib import Path

from seclogx.case import Case
from seclogx.config import BUNDLED_SIGMA_RULES_DIR

_GBK_RULE_TEMPLATE = """\
title: GBK Encoded Rule
id: 11111111-1111-1111-1111-111111111111
status: test
description: 检测可疑进程创建行为
author: 测试作者
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    condition: selection
level: medium
"""


def test_load_rules_handles_non_utf8_locale_encoded_rule_file(tmp_path: Path):
    """A Sigma rule file saved in a non-UTF-8 encoding (e.g. GBK, as a
    Chinese-locale text editor might save it) must not crash `load_rules`
    -- and by extension `hunt()`, which calls it first thing -- with an
    uncaught UnicodeDecodeError. Regression test for the bug reported
    against `hunt()`: rule files were read with `Path.read_text()`, which
    decodes using the OS locale's default codec rather than UTF-8."""
    from seclogx.detect.rules import load_rules

    rule_path = tmp_path / "gbk_rule.yml"
    rule_path.write_bytes(_GBK_RULE_TEMPLATE.encode("gb18030"))

    result = load_rules(tmp_path)

    assert not result.skipped, f"unexpected skipped rules: {result.skipped}"
    assert len(result.rules) == 1
    assert result.rules[0].description == "检测可疑进程创建行为"
    assert str(result.rules[0].author) == "测试作者"


def test_bundled_rules_all_convert():
    from seclogx.detect.backend import DuckDBBackend
    from seclogx.detect.pipeline import seclogx_pipeline
    from seclogx.detect.rules import load_rules

    result = load_rules(BUNDLED_SIGMA_RULES_DIR)
    assert len(result.rules) >= 30, "expected the curated bundled rule set to be present"
    assert not result.skipped, f"unexpected skipped rules: {result.skipped}"

    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
    failures = []
    for rule in result.rules:
        try:
            backend.convert_rule(rule)
        except Exception as e:  # noqa: BLE001
            failures.append((rule.title, str(e)))
    assert not failures, f"rules that failed to convert: {failures}"


def test_hunt_catches_mimikatz_and_not_the_benign_record(synth_case: Case):
    results = synth_case.hunt()
    assert not results.failures, f"unexpected hunt failures: {results.failures}"

    # two bundled rules have "Mimikatz" in the title (a process_creation one and a
    # ps_script one targeting EventID 4104 ScriptBlockText) -- only the
    # process_creation rule should fire against our Sysmon EventID 1 record.
    matched = results.rule_summary[results.rule_summary["matches"] > 0]
    assert len(matched) == 1
    assert "Mimikatz" in matched.iloc[0]["title"]
    assert matched.iloc[0]["matches"] == 1
    assert "T1003.001" in matched.iloc[0]["attack_tags"]

    assert not results.matches.empty
    assert (results.matches["event_data"].str.contains("mimikatz")).all()

    # the benign notepad.exe record shouldn't trip any bundled rule
    assert results.rule_summary["matches"].sum() == 1


def test_hunt_min_level_filters_rules(synth_case: Case):
    results_all = synth_case.hunt()
    results_critical = synth_case.hunt(min_level="critical")
    assert len(results_critical.rule_summary) <= len(results_all.rule_summary)
