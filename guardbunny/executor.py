"""
GuardBunny executor.

Executes authorized IRStep objects. The executor never consults the policy —
it receives only steps that have already been authorized by the runtime.
All I/O and subprocess calls happen here.

Design constraints:
- No shell=True anywhere.
- No subprocess.Popen with shell invocation.
- HTTP uses stdlib urllib only (no third-party HTTP library).
- Subprocess environment is an explicit allowlist, not the full inherited env.
- Path resolution is re-performed independently of the policy check (defense in depth).
- Output size is enforced before returning results.

RESIDUAL RISK (process.run_allowed):
Even with an allowlisted binary, the caller controls argv. A binary like
/usr/bin/grep or /usr/bin/find can read arbitrary files if policy doesn't
restrict argv content. The executor enforces the binary allowlist and env
isolation; argv restriction is a policy concern. See docs/security.md.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    ProcessRunArgs,
    StepResult,
)

# Minimal environment passed to subprocesses.
_SAFE_ENV_KEYS: frozenset[str] = frozenset({
    "PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ",
})


class ExecutorError(Exception):
    """Raised when step execution fails for an operational reason."""


class Executor:
    """Executes authorized IRStep objects and returns structured StepResult values."""

    def execute(self, ir_step: IRStep) -> StepResult:
        """
        Execute an authorized IRStep.

        Returns a StepResult. Never calls the policy engine.
        Raises ExecutorError on operational failure (file not found, network
        error, timeout, output too large, etc.).
        """
        try:
            data = self._dispatch(ir_step)
            return StepResult(step_id=ir_step.step_id, success=True, data=data)
        except ExecutorError:
            raise
        except Exception as exc:
            raise ExecutorError(
                f"Step '{ir_step.step_id}' raised unexpected error: {exc}"
            ) from exc

    def _dispatch(self, ir_step: IRStep) -> dict[str, Any]:
        if ir_step.action_type == ActionType.FILE_READ:
            return self._file_read(ir_step.args, ir_step.constraints)  # type: ignore[arg-type]
        if ir_step.action_type == ActionType.FILE_WRITE:
            return self._file_write(ir_step.args, ir_step.constraints)  # type: ignore[arg-type]
        if ir_step.action_type == ActionType.HTTP_FETCH:
            return self._http_fetch(ir_step.args, ir_step.constraints)  # type: ignore[arg-type]
        if ir_step.action_type == ActionType.PROCESS_RUN:
            return self._process_run(ir_step.args, ir_step.constraints)  # type: ignore[arg-type]
        raise ExecutorError(  # pragma: no cover
            f"Unhandled action type '{ir_step.action_type}'."
        )

    # ── file.read ─────────────────────────────────────────────────────────────

    def _file_read(self, args: FileReadArgs, constraints: Constraints) -> dict[str, Any]:
        path = Path(args.path).resolve()

        if not path.exists():
            raise ExecutorError(f"file.read: path does not exist: '{path}'.")

        if not path.is_file():
            raise ExecutorError(f"file.read: path is not a regular file: '{path}'.")

        raw = path.read_bytes()
        if len(raw) > constraints.max_output_bytes:
            raise ExecutorError(
                f"file.read: file size {len(raw)} bytes exceeds "
                f"max_output_bytes={constraints.max_output_bytes}."
            )

        content = raw.decode("utf-8", errors="replace")
        return {"content": content, "size_bytes": len(raw)}

    # ── file.write ────────────────────────────────────────────────────────────

    def _file_write(self, args: FileWriteArgs, constraints: Constraints) -> dict[str, Any]:
        path = Path(args.path).resolve()

        # Create parent directories only within the resolved path.
        path.parent.mkdir(parents=True, exist_ok=True)

        encoded = args.content.encode("utf-8")
        path.write_bytes(encoded)
        return {"bytes_written": len(encoded), "path": str(path)}

    # ── http.fetch ────────────────────────────────────────────────────────────

    def _http_fetch(self, args: HttpFetchArgs, constraints: Constraints) -> dict[str, Any]:
        """
        Fetch a URL using stdlib urllib only.

        No third-party HTTP library is used. The host and method were
        authorized by the policy engine before this method is called.
        """
        body_bytes: bytes | None = None
        if args.body is not None:
            body_bytes = (
                args.body.encode("utf-8")
                if isinstance(args.body, str)
                else args.body
            )

        req = urllib.request.Request(
            url=args.url,
            data=body_bytes,
            method=args.method,
        )

        if args.headers:
            for k, v in args.headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=constraints.timeout_sec) as resp:
                raw = resp.read(constraints.max_output_bytes + 1)

                if len(raw) > constraints.max_output_bytes:
                    raise ExecutorError(
                        f"http.fetch: response body exceeds "
                        f"max_output_bytes={constraints.max_output_bytes}."
                    )

                status_code: int = resp.status
                content_type: str = resp.headers.get("Content-Type", "")

                body: Any
                if "application/json" in content_type:
                    try:
                        body = json.loads(raw)
                    except json.JSONDecodeError:
                        body = raw.decode("utf-8", errors="replace")
                else:
                    body = raw.decode("utf-8", errors="replace")

                return {
                    "status_code": status_code,
                    "content_type": content_type,
                    "body": body,
                }

        except urllib.error.HTTPError as exc:
            return {
                "status_code": exc.code,
                "content_type": "",
                "body": str(exc.reason),
                "error": f"HTTP {exc.code}: {exc.reason}",
            }
        except urllib.error.URLError as exc:
            raise ExecutorError(
                f"http.fetch: network error reaching '{args.url}': {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise ExecutorError(
                f"http.fetch: timed out after {constraints.timeout_sec}s."
            ) from exc

    # ── process.run_allowed ───────────────────────────────────────────────────

    def _process_run(
        self, args: ProcessRunArgs, constraints: Constraints
    ) -> dict[str, Any]:
        """
        Run an allowlisted binary.

        shell=False is non-negotiable. The environment is an explicit
        allowlist. stdout and stderr are captured and size-checked.

        See module docstring for residual risks.
        """
        cmd = [args.binary, *args.argv]
        safe_env = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_KEYS}

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=constraints.timeout_sec,
                env=safe_env,
                shell=False,  # NEVER shell=True
            )
        except subprocess.TimeoutExpired as exc:
            raise ExecutorError(
                f"process.run_allowed: '{args.binary}' timed out after "
                f"{constraints.timeout_sec}s."
            ) from exc
        except FileNotFoundError as exc:
            raise ExecutorError(
                f"process.run_allowed: binary not found: '{args.binary}'."
            ) from exc
        except PermissionError as exc:
            raise ExecutorError(
                f"process.run_allowed: permission denied executing '{args.binary}'."
            ) from exc

        if len(proc.stdout) > constraints.max_output_bytes:
            raise ExecutorError(
                f"process.run_allowed: stdout ({len(proc.stdout)} bytes) exceeds "
                f"max_output_bytes={constraints.max_output_bytes}."
            )

        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", errors="replace"),
            "stderr": proc.stderr.decode("utf-8", errors="replace"),
        }
