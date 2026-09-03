"""Load Sigma rules from a directory, reporting -- never silently
swallowing -- parse errors and rules whose logsource category isn't
routed by our pipeline (see detect/pipeline.py LOGSOURCE_ROUTES)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from ..textdecode import decode_text
from .pipeline import LOGSOURCE_TABLE


@dataclass
class RuleLoadResult:
    rules: list[SigmaRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)


def load_rules(rules_dir: Path) -> RuleLoadResult:
    rules_dir = Path(rules_dir)
    paths = sorted(set(rules_dir.rglob("*.yml")) | set(rules_dir.rglob("*.yaml")))

    result = RuleLoadResult()
    for path in paths:
        # decode_text() rather than path.read_text(): a bare read_text()
        # decodes using the OS locale's preferred encoding (e.g. GBK/cp936
        # on Chinese-locale Windows), and Sigma rule YAML -- bundled or
        # analyst-supplied -- is conventionally UTF-8, so any non-ASCII
        # content (references, non-English author names, etc.) not valid
        # in that locale's codec raised an uncaught UnicodeDecodeError on
        # every `hunt` run. decode_text() tries UTF-8 first and never
        # raises (see textdecode.py).
        try:
            collection = SigmaCollection.from_yaml(decode_text(path.read_bytes()))
        except SigmaError as e:
            result.skipped.append((str(path), f"parse error: {e}"))
            continue

        for rule in collection.rules:
            category = rule.logsource.category
            if category not in LOGSOURCE_TABLE:
                result.skipped.append(
                    (str(path), f"unsupported logsource category '{category}' (rule '{rule.title}')")
                )
                continue
            result.rules.append(rule)

    return result
