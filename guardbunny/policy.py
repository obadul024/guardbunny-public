"""
GuardBunny policy engine.

Default deny: if an action type is not explicitly listed in allowed_actions,
it is denied. Every allow and deny decision is returned as a PolicyDecision
so the audit layer can record it.

Policy is loaded from a YAML file. The interface — check(ir_step) ->
PolicyDecision — is designed so that an OPA-based policy engine can
replace this module in a future iteration without changing the runtime.

# TODO(future): Replace YAMLPolicy with an OPA client that POST /v1/data/guardbunny/allow.

Shell and interpreter code-execution paths are hard-blocked regardless of
policy configuration. No policy file can enable them.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import yaml

from .urlcheck import UrlError, parse_url

from .models import (
    ActionType,
    Constraints,
    FileReadArgs,
    FileWriteArgs,
    HttpFetchArgs,
    IRStep,
    PolicyDecision,
    ProcessRunArgs,
)

# ── Hard-blocked binaries (policy cannot override) ────────────────────────────

_SHELL_BINARIES: frozenset[str] = frozenset({
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/bin/zsh", "/usr/bin/zsh",
    "/bin/dash", "/usr/bin/dash",
    "/bin/fish", "/usr/bin/fish",
    "/bin/csh", "/usr/bin/csh",
    "/bin/tcsh", "/usr/bin/tcsh",
    "bash", "sh", "zsh", "dash", "fish", "csh", "tcsh",
})

_INTERPRETER_BINARIES: frozenset[str] = frozenset({
    "/usr/bin/python", "/usr/bin/python3",
    "/usr/local/bin/python", "/usr/local/bin/python3",
    "/usr/bin/node", "/usr/local/bin/node",
    "/usr/bin/perl", "/usr/local/bin/perl",
    "/usr/bin/ruby", "/usr/local/bin/ruby",
    "/usr/bin/php", "/usr/local/bin/php",
    "python", "python3", "node", "perl", "ruby", "php",
})

# Flags that let interpreters execute arbitrary code inline.
_CODE_EXEC_FLAGS: frozenset[str] = frozenset({
    "-c", "-e", "-m", "--eval", "--execute", "-exec", "--run",
})


class PolicyError(Exception):
    """Raised when the policy file cannot be loaded or is structurally invalid."""


class Policy:
    """
    YAML-backed policy engine.

    Implements default-deny: any action type not listed in 'allowed_actions'
    is denied before any per-action check runs.

    Each check() call is independent and stateless. The runtime calls check()
    once per step, and once per iteration in repeat loops and per branch in
    condition steps — ensuring no step is ever implicitly authorized.
    """

    def __init__(self, policy_path: str | Path) -> None:
        with open(policy_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            raise PolicyError(
                f"Policy file '{policy_path}' must be a YAML mapping at the top level."
            )
        self._cfg: dict[str, Any] = raw

    def check(self, ir_step: IRStep) -> PolicyDecision:
        """
        Authorize one IRStep against the loaded policy.

        Returns a PolicyDecision with allowed=True or False, a machine-readable
        code, and a human-readable reason. Never raises — always returns a decision.
        """
        action_type = ir_step.action_type

        # Default deny: action type must be explicitly listed.
        allowed_actions: list[str] = self._cfg.get("allowed_actions") or []
        if action_type.value not in allowed_actions:
            return PolicyDecision(
                allowed=False,
                code="ACTION_TYPE_DENIED",
                reason=(
                    f"Action type '{action_type.value}' is not in policy "
                    f"allowed_actions: {allowed_actions}."
                ),
            )

        if action_type == ActionType.FILE_READ:
            return self._check_file_read(ir_step.args)  # type: ignore[arg-type]
        if action_type == ActionType.FILE_WRITE:
            return self._check_file_write(ir_step.args)  # type: ignore[arg-type]
        if action_type == ActionType.HTTP_FETCH:
            return self._check_http_fetch(ir_step.args)  # type: ignore[arg-type]
        if action_type == ActionType.PROCESS_RUN:
            return self._check_process_run(ir_step.args)  # type: ignore[arg-type]

        # Unreachable given the KNOWN_ACTION_TYPES check in ir.py.
        return PolicyDecision(  # pragma: no cover
            allowed=False,
            code="UNHANDLED_ACTION_TYPE",
            reason=f"Action type '{action_type.value}' has no policy handler.",
        )

    def constraints_for(
        self, action_type: ActionType, base: Constraints
    ) -> Constraints:
        """
        Resolve execution constraints from policy with conservative fallbacks.

        Precedence:
          1) execution.* global overrides
          2) per-action section overrides (file_read/http_fetch/process_run/...)
          3) IR defaults (base)
        """
        timeout_sec = base.timeout_sec
        max_output_bytes = base.max_output_bytes

        execution_cfg = self._cfg.get("execution") or {}
        timeout_sec = _maybe_override_positive_int(
            timeout_sec, execution_cfg.get("timeout_sec")
        )
        max_output_bytes = _maybe_override_positive_int(
            max_output_bytes, execution_cfg.get("max_output_bytes")
        )

        section_name = {
            ActionType.FILE_READ: "file_read",
            ActionType.FILE_WRITE: "file_write",
            ActionType.HTTP_FETCH: "http_fetch",
            ActionType.PROCESS_RUN: "process_run",
        }[action_type]
        section_cfg = self._cfg.get(section_name) or {}

        timeout_sec = _maybe_override_positive_int(
            timeout_sec, section_cfg.get("timeout_sec")
        )
        max_output_bytes = _maybe_override_positive_int(
            max_output_bytes, section_cfg.get("max_output_bytes")
        )

        return Constraints(
            timeout_sec=timeout_sec,
            max_output_bytes=max_output_bytes,
        )

    # ── Per-action checks ────────────────────────────────────────────────────

    def _check_file_read(self, args: FileReadArgs) -> PolicyDecision:
        cfg = self._cfg.get("file_read") or {}
        allowed_roots: list[str] = cfg.get("allowed_roots") or []

        if not allowed_roots:
            return PolicyDecision(
                allowed=False,
                code="NO_ALLOWED_ROOTS",
                reason="file.read: no allowed_roots configured in policy.",
            )

        resolved = _resolve_path_safe(args.path)
        if resolved is None:
            return PolicyDecision(
                allowed=False,
                code="PATH_RESOLUTION_FAILED",
                reason=f"file.read: cannot safely resolve path '{args.path}'.",
            )

        for root in allowed_roots:
            root_abs = str(Path(root).resolve())
            if _path_within_root(resolved, root_abs):
                return PolicyDecision(
                    allowed=True,
                    code="ACTION_ALLOWED",
                    reason=(
                        f"file.read: path '{args.path}' is within "
                        f"allowed root '{root}'."
                    ),
                )

        return PolicyDecision(
            allowed=False,
            code="PATH_NOT_IN_ALLOWED_ROOT",
            reason=(
                f"file.read: path '{args.path}' (resolved: '{resolved}') "
                f"is not within any allowed root: {allowed_roots}."
            ),
        )

    def _check_file_write(self, args: FileWriteArgs) -> PolicyDecision:
        cfg = self._cfg.get("file_write") or {}

        if not cfg.get("enabled", False):
            return PolicyDecision(
                allowed=False,
                code="FILE_WRITE_DISABLED",
                reason="file.write: disabled in policy (set file_write.enabled: true to allow).",
            )

        allowed_roots: list[str] = cfg.get("allowed_roots") or []
        if not allowed_roots:
            return PolicyDecision(
                allowed=False,
                code="NO_ALLOWED_ROOTS",
                reason="file.write: no allowed_roots configured in policy.",
            )

        resolved = _resolve_path_safe(args.path)
        if resolved is None:
            return PolicyDecision(
                allowed=False,
                code="PATH_RESOLUTION_FAILED",
                reason=f"file.write: cannot safely resolve path '{args.path}'.",
            )

        for root in allowed_roots:
            root_abs = str(Path(root).resolve())
            if _path_within_root(resolved, root_abs):
                max_bytes: int | None = cfg.get("max_bytes")
                if max_bytes is not None:
                    content_size = len(args.content.encode("utf-8"))
                    if content_size > max_bytes:
                        return PolicyDecision(
                            allowed=False,
                            code="CONTENT_TOO_LARGE",
                            reason=(
                                f"file.write: content is {content_size} bytes; "
                                f"policy max_bytes={max_bytes}."
                            ),
                        )
                return PolicyDecision(
                    allowed=True,
                    code="ACTION_ALLOWED",
                    reason=(
                        f"file.write: path '{args.path}' is within "
                        f"allowed root '{root}'."
                    ),
                )

        return PolicyDecision(
            allowed=False,
            code="PATH_NOT_IN_ALLOWED_ROOT",
            reason=(
                f"file.write: path '{args.path}' (resolved: '{resolved}') "
                f"is not within any allowed root: {allowed_roots}."
            ),
        )

    def _check_http_fetch(self, args: HttpFetchArgs) -> PolicyDecision:
        cfg = self._cfg.get("http_fetch") or {}
        allowed_hosts: list[str] = cfg.get("allowed_hosts") or []
        allowed_methods: list[str] = [
            m.upper() for m in (cfg.get("allowed_methods") or [])
        ]

        if not allowed_hosts:
            return PolicyDecision(
                allowed=False,
                code="NO_ALLOWED_HOSTS",
                reason="http.fetch: no allowed_hosts configured in policy.",
            )

        try:
            host = parse_url(args.url).host
        except UrlError as exc:
            return PolicyDecision(allowed=False, code=exc.code, reason=exc.reason)

        if not _host_matches(host, allowed_hosts):
            return PolicyDecision(
                allowed=False,
                code="HOST_NOT_ALLOWED",
                reason=(
                    f"http.fetch: host '{host}' is not in "
                    f"policy allowed_hosts: {allowed_hosts}."
                ),
            )

        if allowed_methods and args.method.upper() not in allowed_methods:
            return PolicyDecision(
                allowed=False,
                code="METHOD_NOT_ALLOWED",
                reason=(
                    f"http.fetch: method '{args.method}' is not in "
                    f"policy allowed_methods: {allowed_methods}."
                ),
            )

        return PolicyDecision(
            allowed=True,
            code="ACTION_ALLOWED",
            reason=(
                f"http.fetch: '{args.method} {args.url}' is permitted by policy."
            ),
        )

    def _check_process_run(self, args: ProcessRunArgs) -> PolicyDecision:
        # Hard block: shell binaries. Policy cannot override.
        if args.binary in _SHELL_BINARIES:
            return PolicyDecision(
                allowed=False,
                code="SHELL_BINARY_DENIED",
                reason=(
                    f"process.run_allowed: '{args.binary}' is a shell binary. "
                    "Shell execution is permanently blocked regardless of policy."
                ),
            )

        # Hard block: interpreters with code-execution flags. Policy cannot override.
        if args.binary in _INTERPRETER_BINARIES:
            for flag in args.argv:
                if flag in _CODE_EXEC_FLAGS:
                    return PolicyDecision(
                        allowed=False,
                        code="INTERPRETER_CODE_FLAG_DENIED",
                        reason=(
                            f"process.run_allowed: '{args.binary}' called with "
                            f"code-execution flag '{flag}'. "
                            "Arbitrary interpreter execution is permanently blocked."
                        ),
                    )

        cfg = self._cfg.get("process_run") or {}
        allowed_binaries: list[str] = cfg.get("allowed_binaries") or []

        if not allowed_binaries:
            return PolicyDecision(
                allowed=False,
                code="NO_ALLOWED_BINARIES",
                reason=(
                    "process.run_allowed: no allowed_binaries configured in policy."
                ),
            )

        if args.binary not in allowed_binaries:
            return PolicyDecision(
                allowed=False,
                code="BINARY_NOT_ALLOWED",
                reason=(
                    f"process.run_allowed: binary '{args.binary}' is not in "
                    f"policy allowed_binaries: {allowed_binaries}."
                ),
            )

        process_run_rules = self._cfg.get("process_run_rules") or {}
        binary_rule = process_run_rules.get(args.binary)
        if not isinstance(binary_rule, dict):
            return PolicyDecision(
                allowed=False,
                code="PROCESS_RULE_MISSING",
                reason=(
                    f"process.run_allowed: binary '{args.binary}' is allowlisted but has "
                    "no process_run_rules entry."
                ),
            )

        argv_decision = _validate_process_argv(args.binary, args.argv, binary_rule)
        if argv_decision is not None:
            return argv_decision

        return PolicyDecision(
            allowed=True,
            code="ACTION_ALLOWED",
            reason=(
                f"process.run_allowed: binary '{args.binary}' is in policy allowlist."
            ),
        )


# ── Path helpers ──────────────────────────────────────────────────────────────


def _resolve_path_safe(path: str) -> str | None:
    """
    Resolve a path to its absolute canonical form.

    Returns None if the path is clearly malformed (null bytes, invalid chars).
    Uses Path.resolve() which follows symlinks. The policy then checks whether
    the resolved path is within an allowed root using string prefix matching.

    Note: a TOCTOU window exists between policy check and execution. The executor
    performs its own independent path resolution. For stronger guarantees, mount
    the workspace in a separate filesystem and open-at relative to an fd.
    """
    if "\x00" in path:
        return None
    try:
        return str(Path(path).resolve())
    except (ValueError, OSError):
        return None


def _path_within_root(resolved_path: str, root_abs: str) -> bool:
    """
    Return True iff resolved_path is within root_abs (inclusive).

    Uses os.sep to prevent '/allowed_rootsuffix' from matching '/allowed_root'.
    """
    return resolved_path == root_abs or resolved_path.startswith(
        root_abs + os.sep
    )


def _host_matches(host: str, allowed: list[str]) -> bool:
    """Check if host matches any pattern in the allowlist (supports wildcard prefixes)."""
    host = host.lower()
    for pattern in allowed:
        p = pattern.lower()
        if p.startswith("*."):
            if host.endswith(p[1:]):
                return True
        elif p == host:
            return True
    return False


def _maybe_override_positive_int(current: int, maybe_value: Any) -> int:
    if isinstance(maybe_value, int) and maybe_value > 0:
        return maybe_value
    return current


def _deny(code: str, reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, code=code, reason=reason)


def _validate_process_argv(
    binary: str,
    argv: tuple[str, ...],
    rule: dict[str, Any],
) -> PolicyDecision | None:
    allowed_flags = rule.get("allowed_flags")
    if not isinstance(allowed_flags, list) or not all(
        isinstance(x, str) and x.startswith("-") for x in allowed_flags
    ):
        return _deny(
            "PROCESS_RULE_INVALID",
            f"process.run_allowed: invalid allowed_flags for '{binary}'.",
        )

    max_argv = rule.get("max_argv")
    if not isinstance(max_argv, int) or max_argv < 0:
        return _deny(
            "PROCESS_RULE_INVALID",
            f"process.run_allowed: invalid max_argv for '{binary}'.",
        )

    mode = rule.get("file_operand_mode")
    if mode not in {"all_non_flag", "all_non_flag_after_pattern"}:
        return _deny(
            "PROCESS_RULE_INVALID",
            f"process.run_allowed: invalid file_operand_mode for '{binary}'.",
        )

    allowed_file_roots = rule.get("allowed_file_roots")
    if not isinstance(allowed_file_roots, list) or not all(
        isinstance(r, str) and r for r in allowed_file_roots
    ):
        return _deny(
            "PROCESS_RULE_INVALID",
            f"process.run_allowed: invalid allowed_file_roots for '{binary}'.",
        )

    if len(argv) > max_argv:
        return _deny(
            "ARGV_TOO_LONG",
            f"process.run_allowed: argv length {len(argv)} exceeds max_argv={max_argv}.",
        )

    allowed_flag_set = set(allowed_flags)
    i = 0
    saw_pattern = False
    file_operands: list[str] = []

    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return _deny(
                "AMBIGUOUS_ARGV",
                "process.run_allowed: '--' delimiter is not permitted.",
            )

        if tok.startswith("-"):
            if tok not in allowed_flag_set:
                return _deny(
                    "UNEXPECTED_FLAG",
                    f"process.run_allowed: flag '{tok}' is not allowed for '{binary}'.",
                )

            if binary == "/usr/bin/grep" and tok == "-e":
                i += 1
                if i >= len(argv):
                    return _deny(
                        "MISSING_FLAG_VALUE",
                        "process.run_allowed: grep '-e' requires a pattern argument.",
                    )
                saw_pattern = True
                i += 1
                continue

            if binary == "/usr/bin/head" and tok == "-n":
                i += 1
                if i >= len(argv):
                    return _deny(
                        "MISSING_FLAG_VALUE",
                        "process.run_allowed: head '-n' requires a numeric argument.",
                    )
                i += 1
                continue

            i += 1
            continue

        if mode == "all_non_flag":
            file_operands.append(tok)
        elif mode == "all_non_flag_after_pattern":
            if not saw_pattern:
                saw_pattern = True
            else:
                file_operands.append(tok)
        else:
            return _deny(
                "PROCESS_RULE_INVALID",
                f"process.run_allowed: unsupported file_operand_mode '{mode}'.",
            )
        i += 1

    if mode == "all_non_flag_after_pattern" and not saw_pattern:
        return _deny(
            "MISSING_PATTERN",
            "process.run_allowed: grep requires a pattern operand or '-e' pattern.",
        )

    resolved_roots: list[str] = []
    for root in allowed_file_roots:
        resolved_root = _resolve_path_safe(root)
        if resolved_root is None:
            return _deny(
                "PROCESS_RULE_INVALID",
                f"process.run_allowed: invalid allowed_file_root '{root}' for '{binary}'.",
            )
        resolved_roots.append(resolved_root)

    for operand in file_operands:
        if operand == "-":
            return _deny(
                "AMBIGUOUS_ARGV",
                "process.run_allowed: '-' stdin operand is not permitted.",
            )
        resolved_operand = _resolve_path_safe(operand)
        if resolved_operand is None:
            return _deny(
                "INVALID_FILE_OPERAND",
                f"process.run_allowed: cannot resolve file operand '{operand}'.",
            )
        if not any(_path_within_root(resolved_operand, r) for r in resolved_roots):
            return _deny(
                "FILE_OPERAND_OUTSIDE_ALLOWED_ROOT",
                (
                    f"process.run_allowed: file operand '{operand}' "
                    f"(resolved: '{resolved_operand}') is not within allowed roots "
                    f"{allowed_file_roots}."
                ),
            )

    return None
