"""
Security adversarial tests for GuardBunny.

These tests verify that GuardBunny's security model holds against common
attack patterns. Each test represents a real threat scenario.

Tests are organized by threat category:
  - Shell escape attempts
  - Interpreter code execution
  - Path traversal
  - Network exfiltration
  - Resource exhaustion
  - Policy bypass attempts
"""

from pathlib import Path

import pytest
import yaml

from guardbunny.conditions import ConditionError, evaluate_condition
from guardbunny.models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    ProcessRunArgs,
    RuntimeState,
)
from guardbunny.policy import Policy
from guardbunny.runtime import Runtime


def _make_policy(cfg: dict, tmp_path: Path) -> Policy:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(cfg))
    return Policy(p)


def _full_policy(tmp_path: Path, workspace: Path) -> Policy:
    return _make_policy(
        {
            "allowed_actions": [
                "file.read", "file.write", "http.fetch", "process.run_allowed"
            ],
            "file_read": {"allowed_roots": [str(workspace)]},
            "file_write": {"enabled": True, "allowed_roots": [str(workspace)]},
            "http_fetch": {
                "allowed_hosts": ["api.example.com"],
                "allowed_methods": ["GET"],
            },
            "process_run": {"allowed_binaries": ["/usr/bin/grep"]},
            "process_run_rules": {
                "/usr/bin/grep": {
                    "allowed_flags": ["-i", "-n", "-F", "-E", "-e"],
                    "max_argv": 8,
                    "file_operand_mode": "all_non_flag_after_pattern",
                    "allowed_file_roots": [str(workspace)],
                }
            },
        },
        tmp_path,
    )


def _make_ir(action_type, args) -> IRStep:
    return IRStep(
        step_id="adv_test",
        action_type=action_type,
        args=args,
        constraints=Constraints(),
    )


# ── Shell escape ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("binary", [
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/bin/zsh", "/usr/bin/zsh",
    "/bin/dash", "/usr/bin/dash",
    "bash", "sh", "zsh",
])
def test_shell_binary_always_denied(binary: str, tmp_path: Path):
    """All shell binaries must be denied regardless of policy configuration."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary=binary, argv=("-c", "cat /etc/passwd")),
    )
    d = policy.check(ir)
    assert d.allowed is False, f"Shell binary '{binary}' should always be denied"
    assert d.code == "SHELL_BINARY_DENIED"


def test_shell_escape_via_workflow(tmp_path: Path):
    """An LLM-generated workflow requesting bash -c must be denied at runtime."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    workflow = """
version: "1.0"
name: "shell_escape_attempt"
steps:
  - id: escape
    do:
      action: process.run_allowed
      args:
        binary: /bin/bash
        argv: ["-c", "cat /etc/passwd > /tmp/stolen"]
    emit: {}
"""
    result = Runtime(policy=policy).run(workflow, {})
    assert result.status == "denied"
    assert any("SHELL_BINARY_DENIED" in str(e) for e in result.errors)


# ── Interpreter code execution ────────────────────────────────────────────────


@pytest.mark.parametrize("binary,flag", [
    ("/usr/bin/python3", "-c"),
    ("/usr/bin/python", "-c"),
    ("python3", "-c"),
    ("python", "-c"),
    ("/usr/bin/node", "-e"),
    ("node", "-e"),
    ("/usr/bin/perl", "-e"),
    ("perl", "-e"),
    ("/usr/bin/ruby", "-e"),
    ("ruby", "-e"),
])
def test_interpreter_code_flag_always_denied(binary: str, flag: str, tmp_path: Path):
    """Interpreter + code-execution flag must be denied regardless of allowlist."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    # Even with the binary in the allowlist, the code flag must be denied.
    policy = _make_policy(
        {
            "allowed_actions": ["process.run_allowed"],
            "process_run": {"allowed_binaries": [binary]},
        },
        tmp_path,
    )
    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary=binary, argv=(flag, "import os; os.system('id')")),
    )
    d = policy.check(ir)
    assert d.allowed is False, f"'{binary} {flag}' must always be denied"
    assert d.code == "INTERPRETER_CODE_FLAG_DENIED"


# ── Path traversal ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/root/.ssh/id_rsa",
])
def test_absolute_out_of_root_paths_denied(path: str, tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=path))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_path_traversal_denied_read(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    # Traversal to /etc/passwd via ../../
    traversal = str(workspace / ".." / ".." / "etc" / "passwd")
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=traversal))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_path_traversal_denied_write(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    traversal = str(workspace / ".." / "evil.txt")
    ir = _make_ir(ActionType.FILE_WRITE, FileWriteArgs(path=traversal, content="x"))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_null_byte_injection_denied(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    path = str(workspace / "file\x00.txt")
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=path))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_RESOLUTION_FAILED"


def test_workspace_prefix_trick_denied(tmp_path: Path):
    """'/allowed_workspace_suffix' must not match '/allowed_workspace'."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    evil = tmp_path / "ws_evil"
    evil.mkdir()
    policy = _full_policy(tmp_path, workspace)

    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=str(evil / "secret.txt")))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


# ── Network exfiltration ──────────────────────────────────────────────────────


@pytest.mark.parametrize("url", [
    "https://evil.com/exfil",
    "https://attacker.io/steal",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "https://internal.corp.example.net/api",
])
def test_forbidden_hosts_denied(url: str, tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    ir = _make_ir(ActionType.HTTP_FETCH, HttpFetchArgs(url=url, method="GET"))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "HOST_NOT_ALLOWED"


def test_exfil_workflow_denied_end_to_end(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _full_policy(tmp_path, workspace)

    workflow = """
version: "1.0"
name: "exfil_attempt"
steps:
  - id: steal
    do:
      action: http.fetch
      args:
        url: "https://evil.com/collect"
        method: GET
    emit: {}
"""
    result = Runtime(policy=policy).run(workflow, {})
    assert result.status == "denied"


# ── Condition evaluator security ──────────────────────────────────────────────


def test_condition_eval_rejects_import():
    state = RuntimeState(input={})
    with pytest.raises(ConditionError, match="not permitted"):
        evaluate_condition("__import__('os').system('id')", state)


def test_condition_eval_rejects_call():
    state = RuntimeState(input={})
    with pytest.raises(ConditionError, match="not permitted"):
        evaluate_condition("open('/etc/passwd').read()", state)


def test_condition_eval_rejects_subscript():
    state = RuntimeState(input={})
    with pytest.raises(ConditionError, match="not permitted"):
        evaluate_condition("input['key']", state)


def test_condition_eval_rejects_lambda():
    state = RuntimeState(input={})
    with pytest.raises(ConditionError, match="not permitted|invalid syntax"):
        evaluate_condition("(lambda: __import__('os'))()", state)


def test_condition_eval_rejects_unknown_name():
    state = RuntimeState(input={})
    with pytest.raises(ConditionError, match="unknown name"):
        evaluate_condition("evil_module.do_something == True", state)


def test_condition_eval_no_builtins_leak():
    """Builtins must not be accessible via condition expressions."""
    state = RuntimeState(input={})
    # 'eval' would be ast.Call(func=ast.Name(id='eval')) — ast.Call is not allowed.
    with pytest.raises(ConditionError):
        evaluate_condition("eval('1+1') == 2", state)


# ── Resource limits ───────────────────────────────────────────────────────────


def test_repeat_capped_at_max_iterations(tmp_path: Path):
    """Repeat loops must not exceed _MAX_ITERATIONS even if times is larger."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "f.txt").write_text("data")
    policy = _full_policy(tmp_path, workspace)

    # Request 1000 iterations — should be capped to 50 (_MAX_ITERATIONS).
    workflow = f"""
version: "1.0"
name: "resource_exhaustion"
steps:
  - id: loop
    repeat:
      times: 1000
      do:
        action: file.read
        args:
          path: "{workspace}/f.txt"
    emit: {{}}
"""
    result = Runtime(policy=policy).run(workflow, {})
    # The run should complete (not hang), capped at 50 iterations.
    assert result.status == "success"
    # 50 audit records — one per iteration.
    assert len(result.audit) == 50


# ── Action type not in policy ─────────────────────────────────────────────────


def test_file_write_denied_when_not_in_allowed_actions(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _make_policy(
        {
            "allowed_actions": ["file.read"],  # file.write not listed
            "file_read": {"allowed_roots": [str(workspace)]},
            "file_write": {"enabled": True, "allowed_roots": [str(workspace)]},
        },
        tmp_path,
    )
    ir = _make_ir(
        ActionType.FILE_WRITE,
        FileWriteArgs(path=str(workspace / "x.txt"), content="test"),
    )
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "ACTION_TYPE_DENIED"


def test_process_run_denied_when_not_in_allowed_actions(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    policy = _make_policy(
        {
            "allowed_actions": ["file.read"],
            "file_read": {"allowed_roots": [str(workspace)]},
        },
        tmp_path,
    )
    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/grep", argv=("x", str(workspace / "f.txt"))),
    )
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "ACTION_TYPE_DENIED"
