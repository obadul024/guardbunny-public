"""
GuardBunny CLI entry point.

Usage:
  guardbunny <workflow.gb> --policy <policy.yaml> --input <inputs.json>

The CLI is a thin wrapper around Runtime.run(). It loads files, runs the
workflow, prints structured JSON output, and exits non-zero on failure or deny.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy import Policy, PolicyError
from .runtime import Runtime


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="guardbunny",
        description=(
            "GuardBunny — Secure execution gateway for LLM-generated plans.\n"
            "Executes typed, policy-authorized actions. Default deny."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("workflow", help="Path to .gb workflow file.")
    ap.add_argument(
        "--policy", required=True, help="Path to policy YAML file (required)."
    )
    ap.add_argument(
        "--input", required=False, help="Path to JSON inputs file (required)."
    )
    ap.add_argument(
        "--output-format",
        choices=["json", "pretty"],
        default="pretty",
        help="Output format (default: pretty).",
    )
    args = ap.parse_args()

    try:
        policy = Policy(args.policy)
    except (PolicyError, FileNotFoundError, OSError) as exc:
        _die(f"Cannot load policy '{args.policy}': {exc}")

    try:
        workflow_text = Path(args.workflow).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        _die(f"Cannot read workflow '{args.workflow}': {exc}")

    try:
        inputs = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        _die(f"Cannot find inputs file '{args.input}': {exc}")
    except OSError as exc:
        _die(f"Cannot read inputs file '{args.input}': {exc}")
    except json.JSONDecodeError as exc:
        _die(f"Inputs file '{args.input}' is not valid JSON: {exc}")

    runtime = Runtime(policy=policy)
    result = runtime.run(workflow_text, inputs)

    out = {
        "status": result.status,
        "output": result.output,
        "errors": result.errors,
        "steps_executed": result.step_count,
        "audit": result.audit,
    }

    indent = 2 if args.output_format == "pretty" else None
    print(json.dumps(out, ensure_ascii=False, indent=indent))

    if result.status != "success":
        sys.exit(1)


def _die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
