"""
Core data models for GuardBunny.

All models are immutable (frozen dataclasses or NamedTuples) except for
RuntimeState, AuditRecord, and WorkflowResult which are explicitly mutable
by design — they accumulate state during a single run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class ActionType(str, Enum):
    """The complete set of action types GuardBunny supports."""

    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    HTTP_FETCH = "http.fetch"
    PROCESS_RUN = "process.run_allowed"


# ── Typed action argument containers ─────────────────────────────────────────


@dataclass(frozen=True)
class FileReadArgs:
    path: str


@dataclass(frozen=True)
class FileWriteArgs:
    path: str
    content: str


@dataclass(frozen=True)
class HttpFetchArgs:
    url: str
    method: str
    headers: dict[str, str] | None = None
    body: str | None = None


@dataclass(frozen=True)
class ProcessRunArgs:
    binary: str
    argv: tuple[str, ...]


ActionArgs = FileReadArgs | FileWriteArgs | HttpFetchArgs | ProcessRunArgs


# ── Execution constraints ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Constraints:
    """Resource limits applied at execution time, enforced by the executor."""

    timeout_sec: int = 30
    max_output_bytes: int = 65536


# ── Normalized IR ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IRStep:
    """
    Normalized, typed execution unit.

    This is what the policy engine checks and the executor runs.
    The parser produces a WorkflowSpec AST; the ir module resolves
    interpolations into an IRStep at runtime, one step at a time.

    An IRStep is self-contained: it carries everything the policy and
    executor need without consulting the original workflow spec.
    """

    step_id: str
    action_type: ActionType
    args: ActionArgs
    constraints: Constraints


# ── Policy ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyDecision:
    """
    The result of one policy check.

    Every allow AND deny decision is logged. The 'code' field is a
    machine-readable string suitable for log filtering and alerting.
    """

    allowed: bool
    code: str
    reason: str


# ── Execution results ─────────────────────────────────────────────────────────


@dataclass
class StepResult:
    """Structured result of executing one IRStep."""

    step_id: str
    success: bool
    data: dict[str, Any]
    error: str | None = None


@dataclass
class AuditRecord:
    """
    One complete audit event: proposal + decision + execution result.

    Created when a step is proposed, updated when the decision is made,
    updated again when execution completes. Fields are mutable by design.
    """

    step_id: str
    action_type: str
    args_summary: dict[str, Any]
    decision: PolicyDecision
    result_success: bool | None = None
    result_error: str | None = None


# ── Runtime state ─────────────────────────────────────────────────────────────


@dataclass
class RuntimeState:
    """
    Explicit, structured runtime state.

    No loose global key mutation. All state is namespaced:
    - input:  the caller-provided inputs (read-only during execution)
    - steps:  per-step results, keyed by step_id
    - emit:   accumulated output values from emit clauses
    - vars:   runtime variables (e.g. loop.index during repeat)
    """

    input: dict[str, Any]
    steps: dict[str, StepResult] = field(default_factory=dict)
    emit: dict[str, Any] = field(default_factory=dict)
    vars: dict[str, Any] = field(default_factory=dict)


# ── Final result ──────────────────────────────────────────────────────────────


@dataclass
class WorkflowResult:
    """Final structured result returned to the caller."""

    status: Literal["success", "failed", "denied"]
    output: dict[str, Any]
    audit: list[dict[str, Any]]
    errors: list[str]
    step_count: int = 0
