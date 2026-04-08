"""Tests for guardbunny.runtime — end-to-end workflow execution."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from guardbunny.models import PolicyDecision
from guardbunny.policy import Policy
from guardbunny.runtime import Runtime


def _make_policy(cfg: dict, tmp_path: Path) -> Policy:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(cfg))
    return Policy(p)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def rw_policy(tmp_path: Path, workspace: Path) -> Policy:
    return _make_policy(
        {
            "allowed_actions": ["file.read", "file.write"],
            "file_read": {"allowed_roots": [str(workspace)]},
            "file_write": {
                "enabled": True,
                "allowed_roots": [str(workspace)],
            },
        },
        tmp_path,
    )


# ── Successful runs ───────────────────────────────────────────────────────────


def test_file_read_workflow_success(rw_policy: Policy, workspace: Path):
    (workspace / "input.txt").write_text("hello from workspace")

    workflow = f"""
version: "1.0"
name: "read_test"
steps:
  - id: read_file
    do:
      action: file.read
      args:
        path: "{workspace}/input.txt"
    emit:
      content: "${{steps.read_file.result.content}}"
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {})
    assert result.status == "success"
    assert result.output["content"] == "hello from workspace"
    assert result.step_count == 1


def test_file_write_workflow_success(rw_policy: Policy, workspace: Path):
    out_path = workspace / "output.txt"

    workflow = f"""
version: "1.0"
name: "write_test"
steps:
  - id: write_file
    do:
      action: file.write
      args:
        path: "{out_path}"
        content: "written by guardbunny"
    emit:
      bytes_written: "${{steps.write_file.result.bytes_written}}"
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {})
    assert result.status == "success"
    assert out_path.read_text() == "written by guardbunny"


def test_input_interpolation(rw_policy: Policy, workspace: Path):
    (workspace / "dynamic.txt").write_text("dynamic content")

    workflow = f"""
version: "1.0"
name: "interp_test"
steps:
  - id: read_dynamic
    do:
      action: file.read
      args:
        path: "${{input.path}}"
    emit:
      content: "${{steps.read_dynamic.result.content}}"
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {"path": str(workspace / "dynamic.txt")})
    assert result.status == "success"
    assert result.output["content"] == "dynamic content"


def test_condition_then_branch(rw_policy: Policy, workspace: Path):
    (workspace / "a.txt").write_text("branch A")

    workflow = f"""
version: "1.0"
name: "cond_test"
steps:
  - id: branch
    condition:
      test: "input.flag == True"
      then:
        - id: read_a
          do:
            action: file.read
            args:
              path: "{workspace}/a.txt"
          emit:
            result: "${{steps.read_a.result.content}}"
      else: []
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {"flag": True})
    assert result.status == "success"
    assert result.output["result"] == "branch A"


def test_condition_else_branch(rw_policy: Policy, workspace: Path):
    (workspace / "b.txt").write_text("branch B")

    workflow = f"""
version: "1.0"
name: "cond_else"
steps:
  - id: branch
    condition:
      test: "input.flag == True"
      then: []
      else:
        - id: read_b
          do:
            action: file.read
            args:
              path: "{workspace}/b.txt"
          emit:
            result: "${{steps.read_b.result.content}}"
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {"flag": False})
    assert result.status == "success"
    assert result.output["result"] == "branch B"


def test_repeat_accumulates_emit(rw_policy: Policy, workspace: Path):
    """Repeat with merge:append should collect results from each iteration."""
    for i in range(1, 4):
        (workspace / f"item_{i}.txt").write_text(f"item{i}")

    workflow = f"""
version: "1.0"
name: "repeat_test"
steps:
  - id: collect
    repeat:
      times: 3
      do:
        action: file.read
        args:
          path: "{workspace}/item_${{vars.loop.index}}.txt"
    emit:
      items:
        merge: append
        value: "${{steps.collect.result.content}}"
"""
    rt = Runtime(policy=rw_policy)
    result = rt.run(workflow, {})
    assert result.status == "success"
    assert result.output["items"] == ["item1", "item2", "item3"]


# ── Policy re-checks ──────────────────────────────────────────────────────────


def test_repeat_rechecks_policy_every_iteration(tmp_path: Path, workspace: Path):
    """
    The policy must be checked on every repeat iteration.
    We use a mock policy that denies on the 2nd call and verify:
    - The first iteration succeeds.
    - The second is denied.
    - Status is 'denied' (not 'success').
    - The audit log shows two entries.
    """
    (workspace / "f.txt").write_text("data")

    workflow = f"""
version: "1.0"
name: "repeat_recheck"
steps:
  - id: loop_step
    repeat:
      times: 3
      do:
        action: file.read
        args:
          path: "{workspace}/f.txt"
    emit: {{}}
"""
    call_count = 0

    real_policy = _make_policy(
        {
            "allowed_actions": ["file.read"],
            "file_read": {"allowed_roots": [str(workspace)]},
        },
        tmp_path,
    )

    original_check = real_policy.check

    def counting_check(ir_step):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            return PolicyDecision(
                allowed=False, code="TEST_DENY", reason="Denied on iteration 2."
            )
        return original_check(ir_step)

    real_policy.check = counting_check  # type: ignore[method-assign]

    rt = Runtime(policy=real_policy)
    result = rt.run(workflow, {})

    assert result.status == "denied"
    assert call_count == 2  # Proves policy was checked on each iteration


def test_condition_branch_rechecks_policy(tmp_path: Path, workspace: Path):
    """Policy must be checked for sub-steps inside a condition branch."""
    (workspace / "x.txt").write_text("x")

    workflow = f"""
version: "1.0"
name: "cond_recheck"
steps:
  - id: branch
    condition:
      test: "True == True"
      then:
        - id: read_x
          do:
            action: file.read
            args:
              path: "{workspace}/x.txt"
          emit: {{}}
      else: []
"""
    deny_policy = _make_policy(
        {"allowed_actions": [], "file_read": {"allowed_roots": [str(workspace)]}},
        tmp_path,
    )

    rt = Runtime(policy=deny_policy)
    result = rt.run(workflow, {})
    assert result.status == "denied"


# ── Error handling ────────────────────────────────────────────────────────────


def test_parse_error_returns_failed(rw_policy: Policy):
    result = Runtime(policy=rw_policy).run(": : bad yaml [", {})
    assert result.status == "failed"
    assert any("ParseError" in e for e in result.errors)


def test_denied_action_type_returns_denied(tmp_path: Path, workspace: Path):
    deny_policy = _make_policy(
        {"allowed_actions": [], "file_read": {"allowed_roots": [str(workspace)]}},
        tmp_path,
    )
    workflow = f"""
version: "1.0"
name: "denied_test"
steps:
  - id: read
    do:
      action: file.read
      args:
        path: "{workspace}/x.txt"
    emit: {{}}
"""
    result = Runtime(policy=deny_policy).run(workflow, {})
    assert result.status == "denied"


def test_unknown_action_type_returns_failed(rw_policy: Policy):
    workflow = """
version: "1.0"
name: "bad_action"
steps:
  - id: bad
    do:
      action: shell.exec
      args:
        command: id
    emit: {}
"""
    result = Runtime(policy=rw_policy).run(workflow, {})
    assert result.status in {"failed", "denied"}


def test_audit_log_records_allow_and_deny(rw_policy: Policy, workspace: Path):
    (workspace / "present.txt").write_text("here")

    workflow = f"""
version: "1.0"
name: "audit_test"
steps:
  - id: read_ok
    do:
      action: file.read
      args:
        path: "{workspace}/present.txt"
    emit: {{}}
"""
    result = Runtime(policy=rw_policy).run(workflow, {})
    assert result.status == "success"
    assert len(result.audit) == 1
    record = result.audit[0]
    assert record["step_id"] == "read_ok"
    assert record["decision"]["allowed"] is True
    assert record["result_success"] is True
