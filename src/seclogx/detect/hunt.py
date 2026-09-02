"""Run Sigma rules against a case and report matches with ATT&CK context.

Every rule that fails to convert or fails to execute is recorded as a
failure with the reason, alongside rules skipped at load time for an
unsupported logsource category -- a hunt run never silently drops rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
from pathlib import Path

import pandas as pd

from ..attack import parse_attack_tags
from ..config import BUNDLED_SIGMA_RULES_DIR
from ..distributed.config import ClusterConfig
from ..distributed.queue import HUNT_QUEUE_NAME, get_job_queue
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
        self.matches.to_csv(path, index=False, encoding="utf-8")

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


def _evaluate_rules(
    db: CaseDB, backend: DuckDBBackend, rules: list, min_rank: int
) -> tuple[list[pd.DataFrame], list[dict], list[RuleFailure]]:
    """The actual per-rule conversion + DuckDB execution loop -- shared
    verbatim by both the sequential path and each distributed chunk
    worker (see `_hunt_chunk_task`), so distributing hunt work is purely
    an outer fan-out/merge, never a second implementation of rule
    evaluation."""
    match_frames: list[pd.DataFrame] = []
    rule_rows: list[dict] = []
    failures: list[RuleFailure] = []

    for rule in rules:
        level_name = rule.level.name.lower() if rule.level else "unknown"
        if min_rank > -1 and LEVEL_ORDER.get(level_name, -1) < min_rank:
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

    return match_frames, rule_rows, failures


def _chunk_rules(rules: list, chunk_count: int) -> list[list]:
    if not rules:
        return []
    chunk_count = max(1, min(chunk_count, len(rules)))
    size = ceil(len(rules) / chunk_count)
    return [rules[i : i + size] for i in range(0, len(rules), size)]


def _hunt_chunk_task(
    case_dir: Path, rules_dir: Path, rule_ids: list[str], min_rank: int, cluster_config: ClusterConfig
) -> tuple[list[pd.DataFrame], list[dict], list[RuleFailure]]:
    """One distributed-hunt work unit, run inside a `seclogx worker`
    process: re-loads the rule set (Sigma rule objects aren't picklable
    across the queue, so each worker parses `rules_dir` itself rather
    than receiving rule objects), filters to this chunk's `rule_ids`, and
    evaluates them against the shared case via `_evaluate_rules` -- the
    exact same code path the sequential (non-distributed) run uses."""
    load_result = load_rules(rules_dir)
    wanted = set(rule_ids)
    rules = [r for r in load_result.rules if (str(r.id) if r.id else r.title) in wanted]
    db = CaseDB(case_dir, cluster_config=cluster_config)
    backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
    return _evaluate_rules(db, backend, rules, min_rank)


def _run_hunt_distributed(
    case_dir: Path, rules_dir: Path, rules: list, min_rank: int, cluster_config: ClusterConfig, chunk_count: int = 8
) -> tuple[list[pd.DataFrame], list[dict], list[RuleFailure]]:
    queue = get_job_queue(cluster_config, queue_name=HUNT_QUEUE_NAME)
    chunks = _chunk_rules(rules, chunk_count)
    args_list = [
        (case_dir, rules_dir, [str(r.id) if r.id else r.title for r in chunk], min_rank, cluster_config)
        for chunk in chunks
    ]
    results = queue.submit_all(_hunt_chunk_task, args_list)

    match_frames: list[pd.DataFrame] = []
    rule_rows: list[dict] = []
    failures: list[RuleFailure] = []
    for chunk_matches, chunk_rows, chunk_failures in results:
        match_frames.extend(chunk_matches)
        rule_rows.extend(chunk_rows)
        failures.extend(chunk_failures)
    return match_frames, rule_rows, failures


def run_hunt(
    case_dir: Path,
    rules_dir: Path | None = None,
    min_level: str | None = None,
    cluster_config: ClusterConfig | None = None,
) -> HuntResults:
    rules_dir = Path(rules_dir) if rules_dir else BUNDLED_SIGMA_RULES_DIR
    load_result = load_rules(rules_dir)
    cluster_config = cluster_config or ClusterConfig.from_env()
    min_rank = LEVEL_ORDER.get(min_level.lower(), -1) if min_level else -1

    # Distributed mode: independent rules -> independent DuckDB queries,
    # so fanning the rule list out across `seclogx worker` processes is a
    # pure parallel map/merge over `_evaluate_rules`, not a rewrite of it
    # -- see _hunt_chunk_task/_run_hunt_distributed. Sequential mode
    # (default) is completely unchanged from before this branch existed.
    if cluster_config.is_distributed and len(load_result.rules) > 1:
        match_frames, rule_rows, failures = _run_hunt_distributed(
            case_dir, rules_dir, load_result.rules, min_rank, cluster_config
        )
    else:
        db = CaseDB(case_dir, cluster_config=cluster_config)
        backend = DuckDBBackend(processing_pipeline=seclogx_pipeline())
        match_frames, rule_rows, failures = _evaluate_rules(db, backend, load_result.rules, min_rank)

    matches = pd.concat(match_frames, ignore_index=True) if match_frames else pd.DataFrame()
    rule_summary = pd.DataFrame(rule_rows)

    return HuntResults(matches=matches, rule_summary=rule_summary, skipped=load_result.skipped, failures=failures)
