"""
GuardBunny audit log.

Append-only in-memory log of every proposal, policy decision, and
execution result within a single workflow run. Every allow AND deny
decision is recorded before the action is taken.

The log is serialized to a list of dicts at the end of the run and
included in the WorkflowResult. In production, write the log to a
structured sink (JSON Lines file, syslog, SIEM) before returning.

# TODO(future): Add a writer interface for JSON Lines / syslog output.
"""

from __future__ import annotations

from typing import Any

from .models import AuditRecord, PolicyDecision, StepResult


class AuditLog:
    """Append-only audit log for one workflow run."""

    def __init__(self) -> None:
        self._records: list[AuditRecord | dict[str, Any]] = []

    def record_proposal(
        self,
        step_id: str,
        action_type: str,
        args_summary: dict[str, Any],
    ) -> AuditRecord:
        """
        Create and store an audit record for a proposed action.

        Returns the record so the caller can update it with the decision
        and result without a second lookup.
        """
        record = AuditRecord(
            step_id=step_id,
            action_type=action_type,
            args_summary=args_summary,
            decision=PolicyDecision(
                allowed=False,
                code="PENDING",
                reason="Awaiting policy evaluation.",
            ),
        )
        self._records.append(record)
        return record

    def record_decision(self, record: AuditRecord, decision: PolicyDecision) -> None:
        """Update the record with the policy decision."""
        record.decision = decision

    def record_result(self, record: AuditRecord, result: StepResult) -> None:
        """Update the record with the execution result."""
        record.result_success = result.success
        record.result_error = result.error

    def record_condition(
        self,
        step_id: str,
        test: str,
        evaluated_result: bool | None,
        branch_taken: str,
        error: str | None = None,
    ) -> None:
        self._records.append(
            {
                "event": "condition_evaluation",
                "step_id": step_id,
                "test": test,
                "evaluated_result": evaluated_result,
                "branch_taken": branch_taken,
                "error": error,
            }
        )

    def record_runtime_error(self, step_id: str, phase: str, error: str) -> None:
        self._records.append(
            {
                "event": "runtime_error",
                "step_id": step_id,
                "phase": phase,
                "error": error,
            }
        )

    def to_list(self) -> list[dict[str, Any]]:
        """Serialize all records to a list of plain dicts for JSON output."""
        out: list[dict[str, Any]] = []
        for record in self._records:
            if isinstance(record, AuditRecord):
                out.append(_serialize(record))
            else:
                out.append(record)
        return out


def _serialize(record: AuditRecord) -> dict[str, Any]:
    return {
        "step_id": record.step_id,
        "action_type": record.action_type,
        "args_summary": record.args_summary,
        "decision": {
            "allowed": record.decision.allowed,
            "code": record.decision.code,
            "reason": record.decision.reason,
        },
        "result_success": record.result_success,
        "result_error": record.result_error,
    }
