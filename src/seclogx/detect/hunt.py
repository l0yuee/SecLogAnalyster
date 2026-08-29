"""Run Sigma rules against a case and report matches with ATT&CK context.

Every rule that fails to convert or fails to execute is recorded as a
failure with the reason, alongside rules skipped at load time for an
unsupported logsource category -- a hunt run never silently drops rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from ..attack import parse_attack_tags
from ..config import BUNDLED_SIGMA_RULES_DIR
from ..query import CaseDB
from .backend import DuckDBBackend
from .pipeline import LOGSOURCE_TABLE, seclogx_pipeline
from .rules import load_rules

LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class RuleFailure:
    rule_id: str
    title: str
    reason: str


@dataclass
class HuntResults:
    matches: pd.DataFrame
    rule_summary: pd.DataFrame
    skipped: list[tuple[str, str]] = field(default_factory=list)
    failures: list[RuleFailure] = field(default_factory=list)

    def to_dataframe(self) -> pd.DataFrame:
        return self.matches

    def save(self, path: str | Path) -> None:
        self.matches.to_csv(path, index=False)

    def summary_text(self) -> str:
        lines = [
            f"Hunt: {len(self.rule_summary)} rules evaluated, "
            f"{int(self.rule_summary['matches'].sum()) if not self.rule_summary.empty else 0} total matches",
            f"  rules skipped (unsupported logsource): {len(self.skipped)}",
            f"  rules failed (conversion/execution error): {len(self.failures)}",
        ]
        if not self.rule_summary.empty:
            hits = self.rule_summary[self.rule_summary["matches"] > 0].sort_values("matches", ascending=False)
            if not hits.empty:
                lines.append("  rules with matches:")
                for _, row in hits.iterrows():
                    lines.append(
                        f"    [{row['level']}] {row['title']} -- {row['matches']} matches "
                        f"(ATT&CK: {row['attack_tags'] or '-'})"
                    )
        if self.failures:
            lines.append("  failed rules:")
            for f in self.failures:
                lines.append(f"    {f.title} ({f.rule_id}) -- {f.reason}")
        return "\n".join(lines)


def run_hunt(case_dir: Path, rules_dir: Path | None = None, min_level: str | None = None) -> HuntResults:
    rules_dir = Path(rules_dir) if rules_dir else BUNDLED_SIGMA_RULES_DIR
    load_result = load_rules(rules_dir)

    db = CaseDB(case_dir)
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())

    min_rank = LEVEL_ORDER.get(min_level.lower(), -1) if min_level else -1

    match_frames: list[pd.DataFrame] = []
    rule_rows: list[dict] = []
    failures: list[RuleFailure] = []

    for rule in load_result.rules:
        level_name = rule.level.name.lower() if rule.level else "unknown"
        if min_level and LEVEL_ORDER.get(level_name, -1) < min_rank:
            continue

        rule_id = str(rule.id) if rule.id else rule.title
        tags = [str(t) for t in (rule.tags or [])]
        attack_ids = parse_attack_tags(tags)
        table = LOGSOURCE_TABLE.get(rule.logsource.category, "events")

        if table not in db.tables:
            failures.append(
                RuleFailure(rule_id=rule_id, title=rule.title, reason=f"case has no '{table}' table ingested")
            )
            continue

        try:
            fragments = backend.convert_rule(rule)
            condition = fragments[0] if len(fragments) == 1 else "(" + ") OR (".join(fragments) + ")"
        except Exception as e:
            failures.append(RuleFailure(rule_id=rule_id, title=rule.title, reason=f"conversion failed: {e}"))
            continue

        try:
            df = db.sql(f"SELECT * FROM {table} WHERE {condition}")
        except Exception as e:
            failures.append(RuleFailure(rule_id=rule_id, title=rule.title, reason=f"execution failed: {e}"))
            continue

        if not df.empty:
            df = df.copy()
            df["sigma_rule_id"] = rule_id
            df["sigma_rule_title"] = rule.title
            df["sigma_level"] = level_name
            df["sigma_attack_ids"] = ", ".join(attack_ids)
            match_frames.append(df)

        rule_rows.append(
            {
                "rule_id": rule_id,
                "title": rule.title,
                "level": level_name,
                "author": rule.author or "",
                "matches": len(df),
                "attack_tags": ", ".join(attack_ids),
                "references": "; ".join(str(r) for r in (rule.references or [])),
            }
        )

    matches = pd.concat(match_frames, ignore_index=True) if match_frames else pd.DataFrame()
    rule_summary = pd.DataFrame(rule_rows)

    return HuntResults(matches=matches, rule_summary=rule_summary, skipped=load_result.skipped, failures=failures)
