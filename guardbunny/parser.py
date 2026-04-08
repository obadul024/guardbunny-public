"""
GuardBunny workflow parser.

Converts a .gb workflow file (YAML format) into a WorkflowSpec AST.
The parser performs structural validation only — no interpolation resolution,
no policy checks, no I/O. Interpolation expressions like ${input.key} are
preserved as raw strings for the ir module to resolve at execution time.

Step IDs must be valid Python identifiers (alphanumerics and underscores,
not starting with a digit). This constraint exists because condition
expressions reference step results via attribute access syntax
(e.g. steps.my_step.result.value), which requires identifier-safe names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Union

import yaml

_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class ParseError(Exception):
    """Raised when the workflow file has a structural problem."""


# ── AST node types ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ActionSpec:
    """Raw (unresolved) action specification from the workflow file."""

    type: str
    args: dict[str, Any]


@dataclass(frozen=True)
class EmitSpec:
    """An emit clause attached to a step."""

    mappings: dict[str, Any]


@dataclass(frozen=True)
class DoStep:
    """A step that executes exactly one action."""

    id: str
    action: ActionSpec
    emit: EmitSpec


@dataclass(frozen=True)
class ConditionStep:
    """A conditional step. Policy is re-checked for every sub-step in each branch."""

    id: str
    test: str
    then_steps: tuple[StepNode, ...]
    else_steps: tuple[StepNode, ...]


@dataclass(frozen=True)
class RepeatStep:
    """
    A loop step. Policy is re-checked on every iteration.

    'times' may be an integer literal or an interpolation string like
    "${input.count}" that resolves to an integer at runtime.
    """

    id: str
    times: int | str
    action: ActionSpec
    emit: EmitSpec


StepNode = Union[DoStep, ConditionStep, RepeatStep]


@dataclass(frozen=True)
class WorkflowSpec:
    """Parsed, validated workflow AST. Interpolations are unresolved."""

    name: str
    version: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    steps: tuple[StepNode, ...]


# ── Public API ────────────────────────────────────────────────────────────────


def parse(text: str) -> WorkflowSpec:
    """
    Parse a .gb workflow file (YAML) into a WorkflowSpec AST.

    Raises ParseError on any structural problem.
    Does not validate semantic correctness (interpolation targets, types, etc.).
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParseError(f"YAML parse error: {exc}") from exc

    if not isinstance(doc, dict):
        raise ParseError("Workflow must be a YAML mapping at the top level.")

    name = _require_str(doc, "name", "workflow")
    version = _require_str(doc, "version", "workflow")

    input_schema = doc.get("input") or {}
    if not isinstance(input_schema, dict):
        raise ParseError("'input' must be a YAML mapping.")

    output_schema = doc.get("output") or {}
    if not isinstance(output_schema, dict):
        raise ParseError("'output' must be a YAML mapping.")

    raw_steps = doc.get("steps") or []
    if not isinstance(raw_steps, list):
        raise ParseError("'steps' must be a YAML list.")

    steps = tuple(_parse_step(s) for s in raw_steps)

    return WorkflowSpec(
        name=name,
        version=version,
        input_schema=input_schema,
        output_schema=output_schema,
        steps=steps,
    )


# ── Internal parsers ──────────────────────────────────────────────────────────


def _parse_step(raw: Any) -> StepNode:
    if not isinstance(raw, dict):
        raise ParseError(
            f"Each step must be a YAML mapping; got {type(raw).__name__}."
        )

    step_id = _require_str(raw, "id", "step")
    _validate_identifier(step_id)

    if "condition" in raw:
        return _parse_condition_step(step_id, raw["condition"])

    if "repeat" in raw:
        return _parse_repeat_step(step_id, raw["repeat"], raw.get("emit") or {})

    if "do" in raw:
        return _parse_do_step(step_id, raw["do"], raw.get("emit") or {})

    raise ParseError(
        f"Step '{step_id}' must contain one of: 'do', 'condition', 'repeat'."
    )


def _parse_do_step(step_id: str, do_raw: Any, emit_raw: Any) -> DoStep:
    if not isinstance(do_raw, dict):
        raise ParseError(f"Step '{step_id}': 'do' must be a mapping.")

    action_type = _require_str(do_raw, "action", f"step '{step_id}'.do")
    args_raw = do_raw.get("args") or {}
    if not isinstance(args_raw, dict):
        raise ParseError(f"Step '{step_id}': 'do.args' must be a mapping.")

    if not isinstance(emit_raw, dict):
        raise ParseError(f"Step '{step_id}': 'emit' must be a mapping.")

    return DoStep(
        id=step_id,
        action=ActionSpec(type=action_type, args=args_raw),
        emit=EmitSpec(mappings=emit_raw),
    )


def _parse_condition_step(step_id: str, cond_raw: Any) -> ConditionStep:
    if not isinstance(cond_raw, dict):
        raise ParseError(f"Step '{step_id}': 'condition' must be a mapping.")

    test = _require_str(cond_raw, "test", f"step '{step_id}'.condition")

    then_raw = cond_raw.get("then") or []
    else_raw = cond_raw.get("else") or []

    if not isinstance(then_raw, list):
        raise ParseError(f"Step '{step_id}': 'condition.then' must be a list.")
    if not isinstance(else_raw, list):
        raise ParseError(f"Step '{step_id}': 'condition.else' must be a list.")

    return ConditionStep(
        id=step_id,
        test=test,
        then_steps=tuple(_parse_step(s) for s in then_raw),
        else_steps=tuple(_parse_step(s) for s in else_raw),
    )


def _parse_repeat_step(step_id: str, repeat_raw: Any, emit_raw: Any) -> RepeatStep:
    if not isinstance(repeat_raw, dict):
        raise ParseError(f"Step '{step_id}': 'repeat' must be a mapping.")

    times_raw = repeat_raw.get("times")
    if times_raw is None:
        raise ParseError(f"Step '{step_id}': 'repeat.times' is required.")
    if not isinstance(times_raw, (int, str)):
        raise ParseError(
            f"Step '{step_id}': 'repeat.times' must be an integer or interpolation string."
        )

    do_raw = repeat_raw.get("do")
    if do_raw is None:
        raise ParseError(f"Step '{step_id}': 'repeat.do' is required.")
    if not isinstance(do_raw, dict):
        raise ParseError(f"Step '{step_id}': 'repeat.do' must be a mapping.")

    action_type = _require_str(do_raw, "action", f"step '{step_id}'.repeat.do")
    args_raw = do_raw.get("args") or {}
    if not isinstance(args_raw, dict):
        raise ParseError(f"Step '{step_id}': 'repeat.do.args' must be a mapping.")

    if not isinstance(emit_raw, dict):
        raise ParseError(f"Step '{step_id}': 'emit' must be a mapping.")

    return RepeatStep(
        id=step_id,
        times=times_raw,
        action=ActionSpec(type=action_type, args=args_raw),
        emit=EmitSpec(mappings=emit_raw),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _require_str(d: dict[str, Any], key: str, context: str) -> str:
    val = d.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ParseError(
            f"'{key}' is required and must be a non-empty string in {context}."
        )
    return val


def _validate_identifier(step_id: str) -> None:
    if not _IDENTIFIER_RE.match(step_id):
        raise ParseError(
            f"Step id '{step_id}' is not a valid identifier. "
            "Use only letters, digits, and underscores; must not start with a digit. "
            "Hyphens are not allowed because condition expressions use attribute "
            "syntax (steps.step_id.result.key) which requires valid identifiers."
        )
