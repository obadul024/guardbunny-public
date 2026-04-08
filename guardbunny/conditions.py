"""
GuardBunny condition evaluator.

Provides a restricted boolean expression evaluator for condition steps.
It does NOT use eval(). It parses the expression with Python's ast module
and then walks only a strict allowlist of node types.

Supported grammar:
  expr    = comparison | bool_expr | unary_expr | atom
  bool_expr = expr ('and' | 'or') expr
  unary_expr = 'not' expr
  comparison = atom ('==' | '!=' | '<' | '<=' | '>' | '>=') atom
  atom    = NAME ('.' NAME)*    -- variable/attribute access
           | CONSTANT           -- string, int, float, bool, None

Variable namespaces:
  input.key               -- caller-provided input value
  vars.key                -- runtime variables (e.g. vars.loop.index)
  steps.step_id.result.key -- result from a completed step
  emit.key                -- current emit accumulator value

Step IDs in conditions must be valid Python identifiers (enforced by the parser).
"""

from __future__ import annotations

import ast
from typing import Any

from .models import RuntimeState

_ALLOWED_NODE_TYPES: frozenset[type] = frozenset({
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not,
    ast.Compare,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Constant,
    ast.Attribute, ast.Name,
    ast.Load,
})


class ConditionError(Exception):
    """Raised when a condition expression is invalid or cannot be evaluated."""


def evaluate_condition(expr: str, state: RuntimeState) -> bool:
    """
    Safely evaluate a boolean condition expression against runtime state.

    Raises ConditionError if the expression has invalid syntax, uses
    disallowed node types, references unknown variables, or produces
    a non-boolean result.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ConditionError(
            f"Condition '{expr}' has invalid syntax: {exc}"
        ) from exc

    for node in ast.walk(tree):
        if type(node) not in _ALLOWED_NODE_TYPES:
            raise ConditionError(
                f"Condition '{expr}': node type '{type(node).__name__}' is not "
                "permitted. Only comparisons, boolean operators, attribute access, "
                "and constants are supported."
            )

    scope = _build_scope(state)
    evaluator = _Evaluator(scope, expr)
    result = evaluator.visit(tree.body)
    return bool(result)


# ── AST evaluator ─────────────────────────────────────────────────────────────


class _Evaluator(ast.NodeVisitor):
    """
    Strict AST visitor that evaluates only whitelisted node types.

    Any node type not explicitly handled raises ConditionError via
    generic_visit, which prevents unintended evaluation paths.
    """

    def __init__(self, scope: dict[str, Any], expr: str) -> None:
        self._scope = scope
        self._expr = expr

    def visit_Constant(self, node: ast.Constant) -> Any:  # noqa: N802
        return node.value

    def visit_Name(self, node: ast.Name) -> Any:  # noqa: N802
        if node.id not in self._scope:
            raise ConditionError(
                f"Condition '{self._expr}': unknown name '{node.id}'. "
                f"Available names: {sorted(self._scope.keys())}."
            )
        return self._scope[node.id]

    def visit_Attribute(self, node: ast.Attribute) -> Any:  # noqa: N802
        obj = self.visit(node.value)
        if not isinstance(obj, dict):
            raise ConditionError(
                f"Condition '{self._expr}': cannot access attribute '{node.attr}' "
                f"on a non-mapping value (got {type(obj).__name__})."
            )
        if node.attr not in obj:
            raise ConditionError(
                f"Condition '{self._expr}': key '{node.attr}' not found. "
                f"Available keys: {sorted(obj.keys())}."
            )
        return obj[node.attr]

    def visit_Compare(self, node: ast.Compare) -> bool:  # noqa: N802
        left = self.visit(node.left)
        result = True
        for op, comparator_node in zip(node.ops, node.comparators):
            right = self.visit(comparator_node)
            if isinstance(op, ast.Eq):
                step_result = left == right
            elif isinstance(op, ast.NotEq):
                step_result = left != right
            elif isinstance(op, ast.Lt):
                step_result = left < right  # type: ignore[operator]
            elif isinstance(op, ast.LtE):
                step_result = left <= right  # type: ignore[operator]
            elif isinstance(op, ast.Gt):
                step_result = left > right  # type: ignore[operator]
            elif isinstance(op, ast.GtE):
                step_result = left >= right  # type: ignore[operator]
            else:
                raise ConditionError(
                    f"Condition '{self._expr}': unsupported comparison operator "
                    f"'{type(op).__name__}'."
                )
            result = result and step_result
            left = right
        return result

    def visit_BoolOp(self, node: ast.BoolOp) -> bool:  # noqa: N802
        if isinstance(node.op, ast.And):
            return all(self.visit(v) for v in node.values)
        if isinstance(node.op, ast.Or):
            return any(self.visit(v) for v in node.values)
        raise ConditionError(  # pragma: no cover
            f"Condition '{self._expr}': unsupported boolean operator."
        )

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:  # noqa: N802
        if isinstance(node.op, ast.Not):
            return not self.visit(node.operand)
        raise ConditionError(
            f"Condition '{self._expr}': unsupported unary operator "
            f"'{type(node.op).__name__}'."
        )

    def generic_visit(self, node: ast.AST) -> Any:  # noqa: N802
        raise ConditionError(
            f"Condition '{self._expr}': unexpected node type "
            f"'{type(node).__name__}' — not permitted."
        )


def _build_scope(state: RuntimeState) -> dict[str, Any]:
    return {
        "input": state.input,
        "vars": state.vars,
        "steps": {
            sid: {"result": r.data}
            for sid, r in state.steps.items()
        },
        "emit": state.emit,
    }
