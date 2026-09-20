"""Restricted execution boundary for SQL generated from external Sigma rules.

This is defense in depth, not a general SQL sandbox. Rule fields and values
are encoded by DuckDBBackend; only a single, plain SELECT over the expected
case view with supported predicate expressions is admitted here. The caller
may then wrap that SELECT in its own COPY to a private result directory.
"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb

from ..query import CaseDB
from ..paths import duckdb_path

_ALLOWED_FUNCTIONS = {"->>", "like_escape", "not_like_escape", "regexp_matches"}
_ALLOWED_TYPES = {
    "CONSTANT": {"VALUE_CONSTANT"},
    "COLUMN_REF": {"COLUMN_REF"},
    "COMPARISON": {"COMPARE_EQUAL", "COMPARE_NOTEQUAL", "COMPARE_LESSTHAN", "COMPARE_GREATERTHAN",
                   "COMPARE_LESSTHANOREQUALTO", "COMPARE_GREATERTHANOREQUALTO"},
    "CONJUNCTION": {"CONJUNCTION_AND", "CONJUNCTION_OR"},
    "OPERATOR": {"COMPARE_IN", "COMPARE_NOT_IN", "OPERATOR_NOT", "OPERATOR_IS_NULL", "OPERATOR_IS_NOT_NULL"},
}


def _validate_expression(node: dict) -> None:
    kind = node.get("class")
    if kind == "CAST":
        # DuckDB's parser represents SQL true/false as CAST('t'/'f' AS
        # BOOLEAN). Admit this literal shape, not arbitrary cast operands.
        child = node.get("child", {})
        if (node.get("cast_type", {}).get("id") != "BOOLEAN"
                or child.get("class") != "CONSTANT"
                or child.get("value", {}).get("value") not in ("t", "f")):
            raise ValueError("Sigma predicate uses an unsupported SQL cast")
    elif kind == "FUNCTION":
        if (node.get("function_name") not in _ALLOWED_FUNCTIONS
                or node.get("schema") not in ("", "main")
                or node.get("catalog") not in ("", None)
                or node.get("filter") or node.get("distinct") or node.get("export_state")
                or node.get("order_bys", {}).get("orders")):
            raise ValueError("Sigma predicate uses an unsupported SQL function")
    elif node.get("type") not in _ALLOWED_TYPES.get(kind, set()):
        raise ValueError(f"Sigma predicate uses an unsupported SQL expression: {kind}")
    if kind == "COLUMN_REF" and len(node.get("column_names", [])) != 1:
        raise ValueError("Sigma fields must reference an unqualified case column")
    for key in ("left", "right", "child"):
        if node.get(key) is not None:
            _validate_expression(node[key])
    for child in node.get("children", []):
        _validate_expression(child)


def validate_rule_query(con: duckdb.DuckDBPyConnection, query: str, table: str) -> None:
    """Reject extra statements, subqueries, functions and relation changes.

    DuckDB's own parser supplies the AST, so comments and quoted semicolons
    are handled as SQL syntax instead of approximated with a regex.
    Unsupported parser shapes fail closed rather than bypassing validation.
    """
    statements = con.extract_statements(query)
    if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
        raise ValueError("Sigma rule must produce exactly one SELECT statement")
    parsed = json.loads(con.execute("SELECT json_serialize_sql(?)", [query]).fetchone()[0])
    if parsed.get("error") or len(parsed.get("statements", [])) != 1:
        raise ValueError("Sigma rule SQL could not be validated")
    node = parsed["statements"][0]["node"]
    relation = node.get("from_table", {})
    projection = node.get("select_list", [])
    if (node.get("type") != "SELECT_NODE" or node.get("modifiers")
            or node.get("cte_map", {}).get("map")
            or relation.get("type") != "BASE_TABLE" or relation.get("table_name") != table
            or relation.get("schema_name") or relation.get("catalog_name")
            or relation.get("alias") or relation.get("sample") or relation.get("at_clause")
            or node.get("group_expressions") or node.get("group_sets")
            or node.get("having") or node.get("qualify") or node.get("sample")
            or len(projection) != 1 or projection[0].get("class") != "STAR"
            or any(projection[0].get(key) for key in (
                "exclude_list", "replace_list", "rename_list", "expr", "columns", "relation_name"))
            or not node.get("where_clause")):
        raise ValueError("Sigma rule must select case rows with a predicate only")
    _validate_expression(node["where_clause"])


def restrict_hunt_connection(db: CaseDB, output_dir: Path) -> None:
    """Allow only declared lake input and this run's trusted COPY directory.

    Views and a remote backend's credentials/extensions must already have
    been prepared by CaseDB. Configuration is then locked for the remainder
    of this dedicated hunt connection's lifetime. Analyst SQL connections
    are independent and keep their existing behavior.
    """
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    directories = [duckdb_path(output_dir)]
    paths: list[str] = []
    declared = getattr(db, "parquet_files", {})
    for locations in declared.values():
        for location in locations:
            if any(c in location for c in "*?["):
                # Legacy lake globs are restricted to their trusted lake root.
                continue
            paths.append(duckdb_path(location))
    if not declared or any(any(c in p for c in "*?[") for ps in declared.values() for p in ps):
        lake = str(db.lake_dir)
        directories.append(lake.rstrip("/") + "/" if "://" in lake else duckdb_path(lake))
    con = db.connection
    con.execute("SET memory_limit = '512MB'")
    con.execute("SET threads = 2")
    con.execute("SET temp_directory = ?", [duckdb_path(output_dir / "_duckdb_tmp")])
    con.execute("SET allowed_paths = ?", [paths])
    con.execute("SET allowed_directories = ?", [directories])
    con.execute("SET autoinstall_known_extensions = false")
    con.execute("SET autoload_known_extensions = false")
    con.execute("SET enable_external_access = false")
    con.execute("SET lock_configuration = true")
