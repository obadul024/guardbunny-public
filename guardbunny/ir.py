"""
GuardBunny IR normalizer.

Resolves interpolation expressions in parsed AST nodes and produces
typed IRStep objects ready for policy checking and execution.

This module runs at execution time, one step at a time, with access
to the current RuntimeState. It does not perform I/O or policy checks.

Interpolation syntax: ${path.to.value}
  - ${input.key}            — caller-provided input value
  - ${steps.step_id.result.key} — result data from a completed step
  - ${emit.key}             — current emit accumulator value
  - ${vars.key}             — runtime variables (e.g. vars.loop.index)

If an entire value is a single interpolation, the native type is returned
(e.g. an integer stays an integer). If an interpolation is mixed with
literal text, everything is converted to string.
"""

from __future__ import annotations

import re
from typing import Any

from .models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    ProcessRunArgs,
    RuntimeState,
)
from .parser import ActionSpec, EmitSpec

_INTERP_RE = re.compile(r"\$\{([^}]+)\}")

_KNOWN_ACTION_TYPES: frozenset[str] = frozenset(t.value for t in ActionType)

_DEFAULT_CONSTRAINTS = Constraints(timeout_sec=30, max_output_bytes=65536)


class IRError(Exception):
    """Raised when an AST node cannot be normalized into a valid IR step."""


# ── Public API ────────────────────────────────────────────────────────────────


def normalize_do_step(step_id: str, action: ActionSpec, state: RuntimeState) -> IRStep:
    """
    Normalize a DoStep's action into a typed IRStep.

    Resolves all ${...} interpolations against current runtime state.
    Raises IRError if the action type is unknown or required args are missing.
    """
    resolved_args = _resolve_args(action.args, state)
    return _build_ir_step(step_id, action.type, resolved_args)


def normalize_repeat_action(
    step_id: str,
    action: ActionSpec,
    state: RuntimeState,
    iteration: int,
) -> IRStep:
    """
    Normalize the action inside a repeat step for one iteration.

    Makes vars.loop.index available for interpolation (e.g. ${vars.loop.index}).
    Raises IRError if the action type is unknown or required args are missing.
    """
    loop_state = RuntimeState(
        input=state.input,
        steps=state.steps,
        emit=state.emit,
        vars={**state.vars, "loop": {"index": iteration}},
    )
    resolved_args = _resolve_args(action.args, loop_state)
    return _build_ir_step(step_id, action.type, resolved_args)


def resolve_emit(
    emit: EmitSpec, state: RuntimeState, result_data: dict[str, Any]
) -> dict[str, Any]:
    """
    Resolve emit mappings against runtime state and the current step's result.

    'result' is injected directly into the scope so emit clauses can use
    ${result.key} as a shorthand for ${steps.step_id.result.key}.
    """
    scope = _build_scope(state)
    scope["result"] = result_data
    return {k: _resolve_value(v, scope) for k, v in emit.mappings.items()}


def resolve_times(times: int | str, state: RuntimeState) -> int:
    """
    Resolve repeat.times to a concrete integer.

    'times' may already be an int, or an interpolation string like
    "${input.count}" that must resolve to a numeric value.
    """
    if isinstance(times, int):
        return times
    resolved = _resolve_string(times, _build_scope(state))
    try:
        return int(resolved)
    except (ValueError, TypeError) as exc:
        raise IRError(
            f"repeat.times resolved to non-integer value: '{resolved}'"
        ) from exc


# ── Internal ──────────────────────────────────────────────────────────────────


def _build_ir_step(
    step_id: str, action_type_str: str, resolved_args: dict[str, Any]
) -> IRStep:
    if action_type_str not in _KNOWN_ACTION_TYPES:
        raise IRError(
            f"Step '{step_id}': unknown action type '{action_type_str}'. "
            f"Supported types: {sorted(_KNOWN_ACTION_TYPES)}."
        )

    action_type = ActionType(action_type_str)
    args = _build_typed_args(action_type, resolved_args, step_id)

    return IRStep(
        step_id=step_id,
        action_type=action_type,
        args=args,
        constraints=_DEFAULT_CONSTRAINTS,
    )


def _build_typed_args(
    action_type: ActionType, resolved: dict[str, Any], step_id: str
) -> FileReadArgs | FileWriteArgs | HttpFetchArgs | ProcessRunArgs:
    if action_type == ActionType.FILE_READ:
        path = _require_str_arg(resolved, "path", step_id, action_type.value)
        return FileReadArgs(path=path)

    if action_type == ActionType.FILE_WRITE:
        path = _require_str_arg(resolved, "path", step_id, action_type.value)
        content = _require_str_arg(resolved, "content", step_id, action_type.value)
        return FileWriteArgs(path=path, content=content)

    if action_type == ActionType.HTTP_FETCH:
        url = _require_str_arg(resolved, "url", step_id, action_type.value)
        method = resolved.get("method", "GET")
        if not isinstance(method, str):
            raise IRError(
                f"Step '{step_id}': http.fetch 'method' must be a string."
            )
        headers = resolved.get("headers")
        if headers is not None and not isinstance(headers, dict):
            raise IRError(
                f"Step '{step_id}': http.fetch 'headers' must be a mapping."
            )
        body = resolved.get("body")
        body_str = str(body) if body is not None and not isinstance(body, str) else body
        return HttpFetchArgs(
            url=url,
            method=method.upper(),
            headers=headers,
            body=body_str,
        )

    if action_type == ActionType.PROCESS_RUN:
        binary = _require_str_arg(resolved, "binary", step_id, action_type.value)
        argv_raw = resolved.get("argv", [])
        if not isinstance(argv_raw, list):
            raise IRError(
                f"Step '{step_id}': process.run_allowed 'argv' must be a list."
            )
        argv = tuple(str(a) for a in argv_raw)
        return ProcessRunArgs(binary=binary, argv=argv)

    # Unreachable given _KNOWN_ACTION_TYPES guard above.
    raise IRError(f"Unhandled action type '{action_type}'.")  # pragma: no cover


def _resolve_args(raw: dict[str, Any], state: RuntimeState) -> dict[str, Any]:
    scope = _build_scope(state)
    return {k: _resolve_value(v, scope) for k, v in raw.items()}


def _build_scope(state: RuntimeState) -> dict[str, Any]:
    return {
        "input": state.input,
        "steps": {
            sid: {"result": r.data}
            for sid, r in state.steps.items()
        },
        "emit": state.emit,
        "vars": state.vars,
    }


def _resolve_value(value: Any, scope: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _resolve_string(value, scope)
    if isinstance(value, list):
        return [_resolve_value(v, scope) for v in value]
    if isinstance(value, dict):
        return {k: _resolve_value(v, scope) for k, v in value.items()}
    return value


def _resolve_string(template: str, scope: dict[str, Any]) -> Any:
    """
    Resolve ${...} interpolations in a string.

    If the entire string is one interpolation, the native Python type is returned.
    If there are multiple interpolations or mixed literal text, a string is returned.
    """
    matches = list(_INTERP_RE.finditer(template))

    if not matches:
        return template

    # Single bare interpolation — return native type.
    if (
        len(matches) == 1
        and matches[0].start() == 0
        and matches[0].end() == len(template)
    ):
        return _resolve_path(matches[0].group(1), scope, template)

    # Mixed text + interpolations — everything becomes a string.
    def _repl(m: re.Match) -> str:  # type: ignore[type-arg]
        return str(_resolve_path(m.group(1), scope, template))

    return _INTERP_RE.sub(_repl, template)


def _resolve_path(expr: str, scope: dict[str, Any], original: str) -> Any:
    parts = expr.split(".")
    cur: Any = scope
    for part in parts:
        if not isinstance(cur, dict):
            raise IRError(
                f"Interpolation '${{{{expr}}}}' in '{original}': "
                f"expected mapping at '{part}', got {type(cur).__name__}."
            )
        if part not in cur:
            raise IRError(
                f"Interpolation '${{{expr}}}' in '{original}': key '{part}' not found."
            )
        cur = cur[part]
    return cur


def _require_str_arg(
    args: dict[str, Any], key: str, step_id: str, action: str
) -> str:
    val = args.get(key)
    if not isinstance(val, str) or not val:
        raise IRError(
            f"Step '{step_id}': {action} requires '{key}' as a non-empty string."
        )
    return val
