"""Tests for guardbunny.policy — policy decisions for all action types."""

import os
import textwrap
from pathlib import Path

import pytest
import yaml

from guardbunny.models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    ProcessRunArgs,
)
from guardbunny.policy import Policy, PolicyError


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_policy(cfg: dict, tmp_path: Path) -> Policy:
    """Write a policy dict to a temp YAML file and load it."""
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(cfg))
    return Policy(p)


def _make_ir(
    step_id: str,
    action_type: ActionType,
    args: FileReadArgs | FileWriteArgs | HttpFetchArgs | ProcessRunArgs,
) -> IRStep:
    return IRStep(
        step_id=step_id,
        action_type=action_type,
        args=args,
        constraints=Constraints(),
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def default_policy(tmp_path: Path, workspace: Path) -> Policy:
    cfg = {
        "allowed_actions": [
            "file.read", "file.write", "http.fetch", "process.run_allowed"
        ],
        "file_read": {"allowed_roots": [str(workspace)]},
        "file_write": {
            "enabled": True,
            "allowed_roots": [str(workspace)],
            "max_bytes": 1024,
        },
        "http_fetch": {
            "allowed_hosts": ["api.example.com"],
            "allowed_methods": ["GET", "POST"],
        },
        "process_run": {
            "allowed_binaries": ["/usr/bin/grep"],
        },
    }
    return _make_policy(cfg, tmp_path)


# ── file.read ─────────────────────────────────────────────────────────────────


def test_file_read_allowed_inside_root(default_policy: Policy, workspace: Path):
    target = str(workspace / "data.txt")
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path=target))
    d = default_policy.check(ir)
    assert d.allowed is True
    assert d.code == "ACTION_ALLOWED"


def test_file_read_denied_outside_root(default_policy: Policy):
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path="/etc/passwd"))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_file_read_denied_traversal(default_policy: Policy, workspace: Path):
    # Traversal attempt: resolves to /etc/passwd, not within workspace.
    traversal = str(workspace / ".." / ".." / "etc" / "passwd")
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path=traversal))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_file_read_denied_null_byte(default_policy: Policy, workspace: Path):
    path = str(workspace / "file\x00.txt")
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path=path))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_RESOLUTION_FAILED"


def test_file_read_denied_when_action_type_not_allowed(tmp_path: Path, workspace: Path):
    policy = _make_policy(
        {"allowed_actions": [], "file_read": {"allowed_roots": [str(workspace)]}},
        tmp_path,
    )
    target = str(workspace / "x.txt")
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path=target))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "ACTION_TYPE_DENIED"


def test_file_read_denied_when_no_roots_configured(tmp_path: Path):
    policy = _make_policy(
        {"allowed_actions": ["file.read"], "file_read": {"allowed_roots": []}},
        tmp_path,
    )
    ir = _make_ir("s", ActionType.FILE_READ, FileReadArgs(path="/workspace/x.txt"))
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "NO_ALLOWED_ROOTS"


# ── file.write ────────────────────────────────────────────────────────────────


def test_file_write_allowed_inside_root(default_policy: Policy, workspace: Path):
    target = str(workspace / "out.txt")
    ir = _make_ir("s", ActionType.FILE_WRITE, FileWriteArgs(path=target, content="hello"))
    d = default_policy.check(ir)
    assert d.allowed is True


def test_file_write_denied_outside_root(default_policy: Policy):
    ir = _make_ir("s", ActionType.FILE_WRITE, FileWriteArgs(path="/etc/evil", content="x"))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


def test_file_write_denied_when_disabled(tmp_path: Path, workspace: Path):
    policy = _make_policy(
        {
            "allowed_actions": ["file.write"],
            "file_write": {"enabled": False, "allowed_roots": [str(workspace)]},
        },
        tmp_path,
    )
    ir = _make_ir(
        "s", ActionType.FILE_WRITE,
        FileWriteArgs(path=str(workspace / "x.txt"), content="hi")
    )
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "FILE_WRITE_DISABLED"


def test_file_write_denied_content_too_large(default_policy: Policy, workspace: Path):
    big_content = "x" * 2000  # exceeds 1024 byte limit in fixture
    target = str(workspace / "big.txt")
    ir = _make_ir("s", ActionType.FILE_WRITE, FileWriteArgs(path=target, content=big_content))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "CONTENT_TOO_LARGE"


def test_file_write_denied_traversal(default_policy: Policy, workspace: Path):
    path = str(workspace / ".." / "evil.txt")
    ir = _make_ir("s", ActionType.FILE_WRITE, FileWriteArgs(path=path, content="x"))
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "PATH_NOT_IN_ALLOWED_ROOT"


# ── http.fetch ────────────────────────────────────────────────────────────────


def test_http_fetch_allowed(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.HTTP_FETCH,
        HttpFetchArgs(url="https://api.example.com/data", method="GET"),
    )
    d = default_policy.check(ir)
    assert d.allowed is True


def test_http_fetch_denied_forbidden_host(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.HTTP_FETCH,
        HttpFetchArgs(url="https://evil.com/steal", method="GET"),
    )
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "HOST_NOT_ALLOWED"


def test_http_fetch_denied_forbidden_method(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.HTTP_FETCH,
        HttpFetchArgs(url="https://api.example.com/resource", method="DELETE"),
    )
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "METHOD_NOT_ALLOWED"


def test_http_fetch_denied_no_hosts_configured(tmp_path: Path):
    policy = _make_policy(
        {"allowed_actions": ["http.fetch"], "http_fetch": {"allowed_hosts": []}},
        tmp_path,
    )
    ir = _make_ir(
        "s", ActionType.HTTP_FETCH,
        HttpFetchArgs(url="https://api.example.com/data", method="GET"),
    )
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "NO_ALLOWED_HOSTS"


def test_http_fetch_wildcard_host_allowed(tmp_path: Path):
    policy = _make_policy(
        {
            "allowed_actions": ["http.fetch"],
            "http_fetch": {
                "allowed_hosts": ["*.example.com"],
                "allowed_methods": ["GET"],
            },
        },
        tmp_path,
    )
    ir = _make_ir(
        "s", ActionType.HTTP_FETCH,
        HttpFetchArgs(url="https://sub.example.com/data", method="GET"),
    )
    d = policy.check(ir)
    assert d.allowed is True


# ── process.run_allowed ───────────────────────────────────────────────────────


def test_process_run_allowed_for_allowlisted_binary(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/grep", argv=("needle", "/workspace/file.txt")),
    )
    d = default_policy.check(ir)
    assert d.allowed is True


def test_process_run_denied_for_non_allowlisted_binary(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/curl", argv=("https://evil.com",)),
    )
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "BINARY_NOT_ALLOWED"


def test_process_run_denied_bash(default_policy: Policy):
    for binary in ["/bin/bash", "/usr/bin/bash", "bash"]:
        ir = _make_ir(
            "s", ActionType.PROCESS_RUN,
            ProcessRunArgs(binary=binary, argv=("-c", "id")),
        )
        d = default_policy.check(ir)
        assert d.allowed is False, f"Expected bash '{binary}' to be denied"
        assert d.code == "SHELL_BINARY_DENIED"


def test_process_run_denied_sh(default_policy: Policy):
    for binary in ["/bin/sh", "/usr/bin/sh", "sh"]:
        ir = _make_ir(
            "s", ActionType.PROCESS_RUN,
            ProcessRunArgs(binary=binary, argv=("-c", "id")),
        )
        d = default_policy.check(ir)
        assert d.allowed is False
        assert d.code == "SHELL_BINARY_DENIED"


def test_process_run_denied_python_c(default_policy: Policy):
    for binary in ["/usr/bin/python3", "/usr/bin/python", "python3", "python"]:
        ir = _make_ir(
            "s", ActionType.PROCESS_RUN,
            ProcessRunArgs(binary=binary, argv=("-c", "import os; os.system('id')")),
        )
        d = default_policy.check(ir)
        assert d.allowed is False, f"Expected python '{binary} -c' to be denied"
        assert d.code == "INTERPRETER_CODE_FLAG_DENIED"


def test_process_run_denied_node_e(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/node", argv=("-e", "require('child_process').exec('id')")),
    )
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "INTERPRETER_CODE_FLAG_DENIED"


def test_process_run_denied_perl_e(default_policy: Policy):
    ir = _make_ir(
        "s", ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/perl", argv=("-e", "system('id')")),
    )
    d = default_policy.check(ir)
    assert d.allowed is False
    assert d.code == "INTERPRETER_CODE_FLAG_DENIED"


def test_process_run_denied_no_binaries_configured(tmp_path: Path):
    policy = _make_policy(
        {
            "allowed_actions": ["process.run_allowed"],
            "process_run": {"allowed_binaries": []},
        },
        tmp_path,
    )
    ir = _make_ir(
        "s", ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/grep", argv=("x", "/workspace/f.txt")),
    )
    d = policy.check(ir)
    assert d.allowed is False
    assert d.code == "NO_ALLOWED_BINARIES"


# ── Policy file loading ───────────────────────────────────────────────────────


def test_policy_file_not_found():
    with pytest.raises(FileNotFoundError):
        Policy("/nonexistent/policy.yaml")


def test_policy_invalid_yaml_structure(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("- just a list")
    with pytest.raises(PolicyError, match="YAML mapping"):
        Policy(p)
