"""Custom pySigma backend targeting DuckDB SQL.

No official DuckDB (or generic ANSI-SQL) pySigma backend exists (verified
during design). This backend produces a bare boolean WHERE-clause fragment
per rule -- deliberately not a full `SELECT ...` statement, so it stays
decoupled from any particular view/table name. hunt.py wraps the fragment
as `SELECT * FROM events WHERE <fragment>`.

Field names arrive already mapped to full SQL expressions by
detect/pipeline.py's ProcessingPipeline (e.g. Sigma's `Image` becomes
`(event_data ->> 'Image')`), so `field_quote`/`field_escape` are left
unset (no further quoting) and the base class inserts the mapped
expression as-is wherever a template substitutes `{field}`.

`convert_value_str` / `convert_condition_field_eq_val_str` are overridden
(closely following the pattern used by pySigma-backend-sqlite) because the
base `TextQueryBackend` implementation double-quotes values that are
substituted into templates that already carry their own quotes (e.g.
`{field} LIKE '{value}%'`), which produces malformed SQL for
startswith/endswith/contains -- verified empirically before settling on
this override.

Note: the mapped field expressions are parenthesized by the pipeline
(`(event_data ->> 'Image')` rather than `event_data ->> 'Image'`) --
also verified empirically: DuckDB's `->>` operator does not bind as
tightly as expected against `LIKE`/`AND` in a compound WHERE clause, so an
unparenthesized field expression can silently misparse and error at
execution time. Parenthesizing at the field-mapping level fixes every
template uniformly instead of patching each one individually.
"""

from __future__ import annotations

from sigma.conditions import ConditionAND, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.types import SigmaString, SpecialChars


class DuckDBBackend(TextQueryBackend):
    name = "DuckDB backend (seclogx)"
    formats = {"default": "Plain DuckDB SQL WHERE-clause fragment"}
    requires_pipeline = True

    precedence = (ConditionNOT, ConditionAND, ConditionOR)
    parenthesize = True
    group_expression = "({expr})"

    token_separator = " "
    or_token = "OR"
    and_token = "AND"
    not_token = "NOT"
    eq_token = " = "

    # Fields arrive pre-mapped to full (parenthesized) SQL expressions.
    field_quote = None
    field_escape = None

    str_quote = "'"
    escape_char = "\\"
    wildcard_multi = "%"
    wildcard_single = "_"
    add_escaped = "\\"
    bool_values = {True: "true", False: "false"}

    startswith_expression = "{field} LIKE '{value}%' ESCAPE '\\'"
    endswith_expression = "{field} LIKE '%{value}' ESCAPE '\\'"
    contains_expression = "{field} LIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression = "{field} LIKE '{value}' ESCAPE '\\'"

    re_expression = "regexp_matches({field}, '{regex}')"
    re_escape_char = "\\"
    re_escape = ()
    re_escape_escape_char = True

    # Numeric comparison (|lt, |gt, ...) modifiers are not supported in v1 --
    # left unset so rules using them fail conversion explicitly rather than
    # silently producing an incorrect query.

    field_null_expression = "{field} IS NULL"
    field_exists_expression = "{field} IS NOT NULL"
    field_not_exists_expression = "{field} IS NULL"

    convert_or_as_in = True
    convert_and_as_in = False
    in_expressions_allow_wildcards = False
    field_in_list_expression = "{field} {op} ({list})"
    or_in_operator = "IN"
    list_separator = ", "

    deferred_start = ""
    deferred_separator = ""
    deferred_only_query = ""

    def convert_value_str(self, s: SigmaString, state: ConversionState, no_quote: bool = False) -> str:
        converted = s.convert(
            escape_char=self.escape_char,
            wildcard_multi=self.wildcard_multi,
            wildcard_single=self.wildcard_single,
            add_escaped=self.add_escaped,
            filter_chars=self.filter_chars,
        )
        converted = converted.replace("'", "''")  # SQL string quoting: double the single quote
        if self.decide_string_quoting(s) and not no_quote:
            return self.quote_string(converted)
        return converted

    def convert_condition_field_eq_val_str(self, cond, state: ConversionState):
        """Route to startswith/endswith/contains/wildcard templates; suppress the
        base class's default value-quoting for those (the templates already quote)."""
        remove_quote = True
        if (
            self.startswith_expression is not None
            and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[:-1].contains_special()
        ):
            expr, value = self.startswith_expression, cond.value[:-1]
        elif (
            self.endswith_expression is not None
            and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[1:].contains_special()
        ):
            expr, value = self.endswith_expression, cond.value[1:]
        elif (
            self.contains_expression is not None
            and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
            and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[1:-1].contains_special()
        ):
            expr, value = self.contains_expression, cond.value[1:-1]
        elif self.wildcard_match_expression is not None and (
            cond.value.contains_special()
            or self.wildcard_multi in cond.value
            or self.wildcard_single in cond.value
            or self.escape_char in cond.value
        ):
            expr, value = self.wildcard_match_expression, cond.value
        else:
            expr = "{field}" + self.eq_token + "{value}"
            value = cond.value
            remove_quote = False

        return expr.format(
            field=self.escape_and_quote_field(cond.field),
            value=self.convert_value_str(value, state, remove_quote),
        )
