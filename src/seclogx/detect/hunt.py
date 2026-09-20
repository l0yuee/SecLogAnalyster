"""Run Sigma rules with bounded memory and durable, complete match results."""
from __future__ import annotations

from math import ceil
from pathlib import Path
from uuid import uuid4
import json

import pandas as pd
import pyarrow.parquet as pq

from ..attack import parse_attack_tags
from ..config import BUNDLED_SIGMA_RULES_DIR
from ..distributed.config import ClusterConfig
from ..distributed.queue import HUNT_QUEUE_NAME, get_job_queue
from ..query import CaseDB
from ..paths import duckdb_path
from .backend import DuckDBBackend
from .pipeline import LOGSOURCE_TABLE, seclogx_pipeline
from .results import HuntResults, RuleFailure
from .rules import load_rules
from .security import restrict_hunt_connection, validate_rule_query

LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_METADATA_COLUMNS = ["sigma_rule_id", "sigma_rule_title", "sigma_level", "sigma_attack_ids"]


def _evaluate_rules(db: CaseDB, backend: DuckDBBackend, rules: list, min_rank: int,
                    output_dir: Path) -> tuple[list[str], list[dict], list[RuleFailure]]:
    """Write complete per-rule results without materializing matches in Python."""
    restrict_hunt_connection(db, output_dir)
    paths: list[str] = []
    rule_rows: list[dict] = []
    failures: list[RuleFailure] = []
    for rule in rules:
        level_name = rule.level.name.lower() if rule.level else "unknown"
        if min_rank > -1 and LEVEL_ORDER.get(level_name, -1) < min_rank:
            continue
        rule_id = str(rule.id) if rule.id else rule.title
        attack_ids = parse_attack_tags([str(t) for t in (rule.tags or [])])
        table = LOGSOURCE_TABLE.get(rule.logsource.category, "events")
        if table not in db.tables:
            failures.append(RuleFailure(rule_id, rule.title, f"case has no '{table}' table ingested"))
            continue
        try:
            fragments = backend.convert_rule(rule)
            if not fragments or not all(isinstance(fragment, str) and fragment for fragment in fragments):
                raise ValueError("rule produced no SQL predicate")
            condition = fragments[0] if len(fragments) == 1 else "(" + ") OR (".join(fragments) + ")"
            query = f'SELECT * FROM "{table}" WHERE {condition}'
            validate_rule_query(db.connection, query, table)
        except Exception as error:
            failures.append(RuleFailure(rule_id, rule.title, f"conversion failed: {error}"))
            continue
        output = output_dir / f"{uuid4().hex}.parquet"
        partial = output.with_suffix(".partial")
        try:
            # Only this trusted wrapper may COPY. Rule metadata is bound as
            # data and the destination is generated locally, never by a rule.
            destination = duckdb_path(partial).replace("'", "''")
            metadata = ", ".join(f'? AS "{name}"' for name in _METADATA_COLUMNS)
            count = int(db.connection.execute(
                f"COPY (SELECT *, {metadata} FROM ({query}) AS _matches) "
                f"TO '{destination}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 16384)",
                [rule_id, rule.title, level_name, ", ".join(attack_ids)],
            ).fetchone()[0])
            with pq.ParquetFile(duckdb_path(partial)) as parquet:
                if count != parquet.metadata.num_rows:
                    raise RuntimeError("hunt result row count does not match its Parquet metadata")
            if count:
                Path(duckdb_path(partial)).replace(duckdb_path(output))
                paths.append(str(output))
        except Exception as error:
            failures.append(RuleFailure(rule_id, rule.title, f"execution failed: {error}"))
            continue
        finally:
            Path(duckdb_path(partial)).unlink(missing_ok=True)
        rule_rows.append({"rule_id": rule_id, "title": rule.title, "level": level_name,
                          "author": rule.author or "", "matches": count,
                          "attack_tags": ", ".join(attack_ids),
                          "references": "; ".join(str(r) for r in (rule.references or []))})
    return paths, rule_rows, failures


def _chunk_rules(rules: list, chunk_count: int) -> list[list]:
    if not rules:
        return []
    chunk_count = max(1, min(chunk_count, len(rules)))
    size = ceil(len(rules) / chunk_count)
    return [rules[i:i + size] for i in range(0, len(rules), size)]


def _hunt_chunk_task(case_dir: Path, rules_dir: Path, rule_ids: list[str], min_rank: int,
                     cluster_config: ClusterConfig, output_dir: Path):
    """Workers return artifact paths and counts, never match DataFrames.

    Workers require access to the same case directory. Unique subdirectories
    avoid output or DuckDB temporary-file collisions between workers.
    """
    wanted = set(rule_ids)
    rules = [rule for rule in load_rules(rules_dir).rules
             if (str(rule.id) if rule.id else rule.title) in wanted]
    with CaseDB(case_dir, cluster_config=cluster_config) as db:
        return _evaluate_rules(db, DuckDBBackend(processing_pipeline=seclogx_pipeline()), rules,
                               min_rank, output_dir)


def _run_hunt_distributed(case_dir: Path, rules_dir: Path, rules: list, min_rank: int,
                          cluster_config: ClusterConfig, output_dir: Path, chunk_count: int = 8):
    queue = get_job_queue(cluster_config, queue_name=HUNT_QUEUE_NAME)
    args = [(case_dir, rules_dir, [str(rule.id) if rule.id else rule.title for rule in chunk],
             min_rank, cluster_config, output_dir / f"worker-{index}")
            for index, chunk in enumerate(_chunk_rules(rules, chunk_count))]
    results = queue.submit_all(_hunt_chunk_task, args)
    paths: list[str] = []
    rows: list[dict] = []
    failures: list[RuleFailure] = []
    for chunk_paths, chunk_rows, chunk_failures in results:
        paths.extend(chunk_paths)
        rows.extend(chunk_rows)
        failures.extend(chunk_failures)
    return paths, rows, failures


def run_hunt(case_dir: Path, rules_dir: Path | None = None, min_level: str | None = None,
             cluster_config: ClusterConfig | None = None) -> HuntResults:
    case_dir = Path(case_dir).resolve()
    rules_dir = Path(rules_dir).resolve() if rules_dir else BUNDLED_SIGMA_RULES_DIR
    load_result = load_rules(rules_dir)
    cluster_config = cluster_config or ClusterConfig.from_env()
    min_rank = LEVEL_ORDER.get(min_level.lower(), -1) if min_level else -1
    output_dir = case_dir / "hunts" / uuid4().hex
    output_dir.mkdir(parents=True)
    if cluster_config.is_distributed and len(load_result.rules) > 1:
        paths, rows, failures = _run_hunt_distributed(case_dir, rules_dir, load_result.rules, min_rank,
                                                    cluster_config, output_dir)
    else:
        with CaseDB(case_dir, cluster_config=cluster_config) as db:
            paths, rows, failures = _evaluate_rules(db, DuckDBBackend(processing_pipeline=seclogx_pipeline()),
                                                    load_result.rules, min_rank, output_dir)
    result = HuntResults(rule_summary=pd.DataFrame(rows), result_dir=output_dir, files=paths,
                         skipped=load_result.skipped, failures=failures)
    manifest = {"version": 1, "total_matches": result.total_matches,
                "files": [str(Path(path).relative_to(output_dir)) for path in paths],
                "rule_summary": rows, "skipped": load_result.skipped,
                "failures": [vars(failure) for failure in failures]}
    (output_dir / "results.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    result._load_small()
    return result
