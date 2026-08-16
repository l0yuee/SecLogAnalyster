"""Load Sigma rules from a directory, reporting -- never silently
swallowing -- parse errors and rules whose logsource category isn't
routed by our pipeline (see detect/pipeline.py LOGSOURCE_ROUTES)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from .pipeline import LOGSOURCE_ROUTES


@dataclass
class RuleLoadResult:
    rules: list[SigmaRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)


def load_rules(rules_dir: Path) -> RuleLoadResult:
    rules_dir = Path(rules_dir)
    paths = sorted(set(rules_dir.rglob("*.yml")) | set(rules_dir.rglob("*.yaml")))

    result = RuleLoadResult()
    for path in paths:
        try:
            collection = SigmaCollection.from_yaml(path.read_text())
        except SigmaError as e:
            result.skipped.append((str(path), f"parse error: {e}"))
            continue

        for rule in collection.rules:
            category = rule.logsource.category
            if category not in LOGSOURCE_ROUTES:
                result.skipped.append(
                    (str(path), f"unsupported logsource category '{category}' (rule '{rule.title}')")
                )
                continue
            result.rules.append(rule)

    return result
