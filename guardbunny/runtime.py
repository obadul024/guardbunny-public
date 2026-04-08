"""
GuardBunny runtime — the authoritative execution orchestrator.

Trust boundary: everything that enters this module from outside is untrusted.
  - workflow_text: produced by an LLM or user — treat as adversarial input.
  - inputs: caller-provided — validate against the workflow's input_schema.

The runtime owns the pipeline:
  parse -> normalize IR -> policy check -> execute -> audit -> emit

Key security invariants enforced here:
  1. Every step is policy-checked immediately before execution.
  2. Repeat loops re-check policy on every iteration.
  3. Condition branches re-check policy for every sub-step.
  4. No step result is used before it has been recorded in state.
  5. State is updated atomically after each step (no partial updates).
  6. run() never raises — all errors are captured in WorkflowResult.
"""

from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .conditions import ConditionError, evaluate_condition
from .executor import Executor, ExecutorError
from .ir import (
    IRError,
    normalize_do_step,
    normalize_repeat_action,
    resolve_emit,
    resolve_times,
)
from .models import (
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    PolicyDecision,
    ProcessRunArgs,
    RuntimeState,
    StepResult,
    WorkflowResult,
)
from .parser import ConditionStep, DoStep, ParseError, RepeatStep, StepNode, parse
from .policy import Policy

_MAX_STEPS = 100
_MAX_ITERATIONS = 50


class PolicyDeniedError(Exception):
    """Raised internally when a step is denied. Caught by run() and recorded."""

    def __init__(self, step_id: str, decision: PolicyDecision) -> None:
        self.step_id = step_id
        self.decision = decision
        super().__init__(
            f"Step '{step_id}' denied: [{decision.code}] {decision.reason}"
        )


class Runtime:
    """
    GuardBunny secure execution runtime.

    Instantiate with a Policy object. Call run() for each workflow execution.
    A single Runtime instance may be reused across multiple run() calls.
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._executor = Executor()

    def run(self, workflow_text: str, inputs: dict[str, Any]) -> WorkflowResult:
        """
        Execute a workflow against a set of inputs.

        Returns a WorkflowResult with status, output, audit log, and errors.
        Never raises — all errors are captured in WorkflowResult.errors.
        """
        audit = AuditLog()

        try:
            spec = parse(workflow_text)
        except ParseError as exc:
            return WorkflowResult(
                status="failed",
                output={},
                audit=audit.to_list(),
                errors=[f"ParseError: {exc}"],
            )

        state = RuntimeState(input=inputs)
        step_count = 0

        try:
            for step in spec.steps:
                step_count += 1
                if step_count > _MAX_STEPS:
                    raise RuntimeError(
                        f"Exceeded maximum step count ({_MAX_STEPS}). "
                        "Increase _MAX_STEPS or split into multiple workflows."
                    )
                self._execute_step(step, state, audit)

        except PolicyDeniedError as exc:
            return WorkflowResult(
                status="denied",
                output={},
                audit=audit.to_list(),
                errors=[str(exc)],
                step_count=step_count,
            )
        except (IRError, ExecutorError, ConditionError, RuntimeError) as exc:
            return WorkflowResult(
                status="failed",
                output={},
                audit=audit.to_list(),
                errors=[str(exc)],
                step_count=step_count,
            )

        return WorkflowResult(
            status="success",
            output=dict(state.emit),
            audit=audit.to_list(),
            errors=[],
            step_count=step_count,
        )

    # ── Step dispatchers ──────────────────────────────────────────────────────

    def _execute_step(
        self, step: StepNode, state: RuntimeState, audit: AuditLog
    ) -> None:
        if isinstance(step, DoStep):
            self._execute_do(step, state, audit)
        elif isinstance(step, ConditionStep):
            self._execute_condition(step, state, audit)
        elif isinstance(step, RepeatStep):
            self._execute_repeat(step, state, audit)
        else:
            raise RuntimeError(  # pragma: no cover
                f"Unknown step type: {type(step).__name__}."
            )

    def _execute_do(
        self, step: DoStep, state: RuntimeState, audit: AuditLog
    ) -> None:
        ir_step = normalize_do_step(step.id, step.action, state)

        args_summary = _summarize_args(ir_step)
        record = audit.record_proposal(step.id, ir_step.action_type.value, args_summary)

        # Policy check — mandatory before every execution.
        decision = self._policy.check(ir_step)
        audit.record_decision(record, decision)

        if not decision.allowed:
            raise PolicyDeniedError(step.id, decision)

        result = self._executor.execute(ir_step)
        audit.record_result(record, result)

        if not result.success:
            raise ExecutorError(f"Step '{step.id}' failed: {result.error}")

        # Record result in state BEFORE resolving emit so that
        # ${steps.step_id.result.key} works in the emit clause.
        state.steps[step.id] = result
        resolved_emit = resolve_emit(step.emit, state, result.data)
        _apply_emit(resolved_emit, state)

    def _execute_condition(
        self, step: ConditionStep, state: RuntimeState, audit: AuditLog
    ) -> None:
        ok = evaluate_condition(step.test, state)
        branch = step.then_steps if ok else step.else_steps
        # Policy is re-checked for every sub-step in the taken branch.
        for sub_step in branch:
            self._execute_step(sub_step, state, audit)

    def _execute_repeat(
        self, step: RepeatStep, state: RuntimeState, audit: AuditLog
    ) -> None:
        times = resolve_times(step.times, state)
        times = min(times, _MAX_ITERATIONS)

        for i in range(1, times + 1):
            # Make loop.index available to interpolations inside the action args.
            state.vars["loop"] = {"index": i}

            ir_step = normalize_repeat_action(step.id, step.action, state, i)

            args_summary = _summarize_args(ir_step)
            record = audit.record_proposal(
                f"{step.id}[{i}]", ir_step.action_type.value, args_summary
            )

            # Policy is re-checked on EVERY iteration — not once for the loop.
            decision = self._policy.check(ir_step)
            audit.record_decision(record, decision)

            if not decision.allowed:
                raise PolicyDeniedError(f"{step.id}[{i}]", decision)

            result = self._executor.execute(ir_step)
            audit.record_result(record, result)

            if not result.success:
                raise ExecutorError(
                    f"Step '{step.id}' iteration {i} failed: {result.error}"
                )

            state.steps[step.id] = result
            resolved_emit = resolve_emit(step.emit, state, result.data)
            _apply_emit(resolved_emit, state)

        # Clean up the loop variable after the repeat finishes.
        state.vars.pop("loop", None)


# ── Emit helpers ──────────────────────────────────────────────────────────────


def _apply_emit(resolved: dict[str, Any], state: RuntimeState) -> None:
    """
    Apply resolved emit mappings to state.emit.

    Supports 'merge: append' for accumulating list results across iterations.
    Any other value overwrites the existing key.
    """
    for key, value in resolved.items():
        if (
            isinstance(value, dict)
            and value.get("merge") == "append"
        ):
            existing = state.emit.setdefault(key, [])
            val = value.get("value")
            if isinstance(val, list):
                existing.extend(val)
            else:
                existing.append(val)
        else:
            state.emit[key] = value


def _summarize_args(ir_step: IRStep) -> dict[str, Any]:
    """
    Produce a sanitized summary of action args for the audit log.

    Deliberately omits content bodies (file content, HTTP bodies) to avoid
    leaking sensitive data into audit records. Paths, URLs, and binary names
    are included because they are needed for security review.
    """
    args = ir_step.args
    if isinstance(args, FileReadArgs):
        return {"path": args.path}
    if isinstance(args, FileWriteArgs):
        return {"path": args.path, "content_bytes": len(args.content.encode("utf-8"))}
    if isinstance(args, HttpFetchArgs):
        return {"method": args.method, "url": args.url}
    if isinstance(args, ProcessRunArgs):
        return {"binary": args.binary, "argv": list(args.argv)}
    return {}  # pragma: no cover
