"""Small bundled MITRE ATT&CK technique-id -> name/tactic lookup.

Deliberately NOT exhaustive -- covers the techniques referenced by the
bundled curated Sigma rule set (data/sigma_rules/), not the full ATT&CK
framework. No live MITRE fetch in v1; this needs periodic manual refresh
as bundled rules change (see docs/known_limitations.md). Unknown IDs
simply aren't enriched (name/tactic come back None) rather than guessed.
"""

from __future__ import annotations

import json
from functools import lru_cache

from .config import BUNDLED_ATTACK_DATA


@lru_cache(maxsize=1)
def _techniques() -> dict[str, dict[str, str]]:
    if not BUNDLED_ATTACK_DATA.exists():
        return {}
    return json.loads(BUNDLED_ATTACK_DATA.read_text())


def lookup_technique(technique_id: str) -> dict[str, str] | None:
    """`technique_id` may be like 't1059.001' or 'T1059.001'."""
    return _techniques().get(technique_id.upper())


def parse_attack_tags(tags: list[str]) -> list[str]:
    """Extract bare technique IDs (e.g. 'T1059.001') from Sigma tag strings
    like 'attack.t1059.001'."""
    ids = []
    for tag in tags:
        t = str(tag)
        if t.lower().startswith("attack.t"):
            ids.append(t.split(".", 1)[1].upper())
    return ids
