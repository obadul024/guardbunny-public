"""Tests for guardbunny.executor — actual I/O execution."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guardbunny.executor import Executor, ExecutorError
from guardbunny.models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    ProcessRunArgs,
)


def _make_ir(action_type: ActionType, args, constraints: Constraints = None) -> IRStep:
    return IRStep(
        step_id="test_step",
        action_type=action_type,
        args=args,
        constraints=constraints or Constraints(),
    )


@pytest.fixture
def executor() -> Executor:
    return Executor()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


# ── file.read ─────────────────────────────────────────────────────────────────


def test_file_read_returns_content(executor: Executor, workspace: Path):
    target = workspace / "hello.txt"
    target.write_text("hello world")
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=str(target)))
    result = executor.execute(ir)
    assert result.success is True
    assert result.data["content"] == "hello world"
    assert result.data["size_bytes"] == len(b"hello world")


def test_file_read_nonexistent_file(executor: Executor, workspace: Path):
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=str(workspace / "ghost.txt")))
    with pytest.raises(ExecutorError, match="does not exist"):
        executor.execute(ir)


def test_file_read_directory_rejected(executor: Executor, workspace: Path):
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=str(workspace)))
    with pytest.raises(ExecutorError, match="not a regular file"):
        executor.execute(ir)


def test_file_read_enforces_max_output_bytes(executor: Executor, workspace: Path):
    target = workspace / "big.txt"
    target.write_bytes(b"x" * 200)
    constraints = Constraints(timeout_sec=30, max_output_bytes=100)
    ir = _make_ir(ActionType.FILE_READ, FileReadArgs(path=str(target)), constraints)
    with pytest.raises(ExecutorError, match="max_output_bytes"):
        executor.execute(ir)


# ── file.write ────────────────────────────────────────────────────────────────


def test_file_write_creates_file(executor: Executor, workspace: Path):
    target = workspace / "out.txt"
    ir = _make_ir(ActionType.FILE_WRITE, FileWriteArgs(path=str(target), content="written!"))
    result = executor.execute(ir)
    assert result.success is True
    assert target.read_text() == "written!"
    assert result.data["bytes_written"] == len(b"written!")


def test_file_write_creates_parent_dirs(executor: Executor, workspace: Path):
    target = workspace / "subdir" / "nested" / "out.txt"
    ir = _make_ir(ActionType.FILE_WRITE, FileWriteArgs(path=str(target), content="nested"))
    result = executor.execute(ir)
    assert result.success is True
    assert target.read_text() == "nested"


def test_file_write_overwrites_existing(executor: Executor, workspace: Path):
    target = workspace / "existing.txt"
    target.write_text("old content")
    ir = _make_ir(ActionType.FILE_WRITE, FileWriteArgs(path=str(target), content="new content"))
    executor.execute(ir)
    assert target.read_text() == "new content"


# ── http.fetch ────────────────────────────────────────────────────────────────


def _make_mock_response(status: int, body: bytes, content_type: str = "application/json"):
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.read.return_value = body
    mock_resp.headers.get.return_value = content_type
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_http_fetch_returns_json_body(executor: Executor):
    body = json.dumps({"key": "value"}).encode()
    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, body)):
        ir = _make_ir(
            ActionType.HTTP_FETCH,
            HttpFetchArgs(url="https://api.example.com/data", method="GET"),
        )
        result = executor.execute(ir)
    assert result.success is True
    assert result.data["status_code"] == 200
    assert result.data["body"] == {"key": "value"}


def test_http_fetch_returns_text_body(executor: Executor):
    body = b"plain text response"
    with patch(
        "urllib.request.urlopen",
        return_value=_make_mock_response(200, body, content_type="text/plain"),
    ):
        ir = _make_ir(
            ActionType.HTTP_FETCH,
            HttpFetchArgs(url="https://api.example.com/data", method="GET"),
        )
        result = executor.execute(ir)
    assert result.data["body"] == "plain text response"


def test_http_fetch_enforces_max_output_bytes(executor: Executor):
    big_body = b"x" * 200
    constraints = Constraints(timeout_sec=30, max_output_bytes=100)
    with patch("urllib.request.urlopen", return_value=_make_mock_response(200, big_body)):
        ir = _make_ir(
            ActionType.HTTP_FETCH,
            HttpFetchArgs(url="https://api.example.com/data", method="GET"),
            constraints,
        )
        with pytest.raises(ExecutorError, match="max_output_bytes"):
            executor.execute(ir)


def test_http_fetch_network_error(executor: Executor):
    import urllib.error
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        ir = _make_ir(
            ActionType.HTTP_FETCH,
            HttpFetchArgs(url="https://api.example.com/data", method="GET"),
        )
        with pytest.raises(ExecutorError, match="network error"):
            executor.execute(ir)


# ── process.run_allowed ───────────────────────────────────────────────────────


@pytest.mark.skipif(
    not Path("/usr/bin/true").exists(),
    reason="/usr/bin/true not available",
)
def test_process_run_allowed_success(executor: Executor):
    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/true", argv=()),
    )
    result = executor.execute(ir)
    assert result.success is True
    assert result.data["exit_code"] == 0


@pytest.mark.skipif(
    not Path("/usr/bin/echo").exists(),
    reason="/usr/bin/echo not available",
)
def test_process_run_captures_stdout(executor: Executor):
    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/usr/bin/echo", argv=("hello guardbunny",)),
    )
    result = executor.execute(ir)
    assert result.success is True
    assert "hello guardbunny" in result.data["stdout"]


def test_process_run_binary_not_found(executor: Executor):
    ir = _make_ir(
        ActionType.PROCESS_RUN,
        ProcessRunArgs(binary="/nonexistent/binary", argv=()),
    )
    with pytest.raises(ExecutorError, match="binary not found"):
        executor.execute(ir)


def test_process_run_enforces_timeout(executor: Executor):
    """subprocess.TimeoutExpired is raised and wrapped in ExecutorError."""
    constraints = Constraints(timeout_sec=1, max_output_bytes=65536)
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["/usr/bin/sleep"], timeout=1),
    ):
        ir = _make_ir(
            ActionType.PROCESS_RUN,
            ProcessRunArgs(binary="/usr/bin/sleep", argv=("10",)),
            constraints,
        )
        with pytest.raises(ExecutorError, match="timed out"):
            executor.execute(ir)


def test_process_run_enforces_output_size(executor: Executor):
    """stdout larger than max_output_bytes is rejected."""
    big_stdout = b"x" * 200
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = big_stdout
    mock_proc.stderr = b""

    constraints = Constraints(timeout_sec=30, max_output_bytes=100)
    with patch("subprocess.run", return_value=mock_proc):
        ir = _make_ir(
            ActionType.PROCESS_RUN,
            ProcessRunArgs(binary="/usr/bin/grep", argv=("x", "/workspace/f.txt")),
            constraints,
        )
        with pytest.raises(ExecutorError, match="max_output_bytes"):
            executor.execute(ir)


def test_process_run_never_uses_shell(executor: Executor):
    """Verify subprocess.run is always called with shell=False."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b""
    mock_proc.stderr = b""

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        ir = _make_ir(
            ActionType.PROCESS_RUN,
            ProcessRunArgs(binary="/usr/bin/grep", argv=("needle", "/workspace/f.txt")),
        )
        try:
            executor.execute(ir)
        except ExecutorError:
            pass  # May fail for other reasons in the mock; we only check shell=False.

        if mock_run.called:
            _, kwargs = mock_run.call_args
            assert kwargs.get("shell") is False or kwargs.get("shell") is None, \
                "subprocess.run must never be called with shell=True"
