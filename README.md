# GuardBunny

**A secure execution gateway for LLM-generated plans.**

GuardBunny bridges the gap between what an LLM proposes and what actually runs on your system. It treats every LLM-produced plan as untrusted input, normalizes it into typed actions, checks each action against a policy, and executes only what is explicitly allowed.

---

## What GuardBunny Is

- A **bounded execution runtime** — supports exactly four action types, nothing more
- A **typed action gateway** — every action is a typed IR object, not a free-form string
- A **policy-enforced planner/executor bridge** — default deny, every decision logged

## What GuardBunny Is NOT

- Not a general prompt language
- Not a general-purpose programming language
- Not a broad agent framework
- Not a shell wrapper with safety theater around it

---

## Trust Boundary

```text
LLM / plan text (UNTRUSTED)
        │
        ▼
    [ parser ]         structural validation
        │
        ▼
     [ AST ]           unresolved, typed
        │
        ▼
  [ IR normalizer ]    interpolation resolved at runtime
        │
        ▼
  [ policy engine ]    default deny — every action authorized here
        │
        ▼
    [ executor ]       I/O happens here, never with shell=True
        │
        ▼
   [ audit log ]       every proposal, decision, and result recorded
        │
        ▼
 structured result
```

The LLM is a **planner only**. The runtime is **authoritative**.

---

## Supported Action Types

| Action | What it does |
| ------ | ------------ |
| `file.read` | Read a file from an allowlisted root |
| `file.write` | Write a file to an allowlisted root |
| `http.fetch` | HTTP request to an allowlisted host |
| `process.run_allowed` | Run an explicitly allowlisted binary (no shell) |

Shell execution (`bash`, `sh`, etc.) is **permanently blocked**. No policy can enable it.

---

## Quickstart

```bash
# Install
pip install -e ".[dev]"

# Create a workspace
mkdir -p /tmp/guardbunny/workspace
echo "hello from workspace" > /tmp/guardbunny/workspace/hello.txt

# Run the safe_read example
guardbunny examples/safe_read.gb \
    --policy policies/default_policy.yaml \
    --input /dev/stdin <<'EOF'
{"file_path": "/tmp/guardbunny/workspace/hello.txt"}
EOF

# Run tests
pytest tests/ -v
```

---

## Example Workflow

```yaml
# examples/safe_read.gb
version: "1.0"
name: "safe_read"

input:
  file_path:
    type: string

output:
  content:
    type: string

steps:
  - id: read_file
    do:
      action: file.read
      args:
        path: "${input.file_path}"
    emit:
      content: "${steps.read_file.result.content}"
```

Run it:

```bash
guardbunny examples/safe_read.gb \
    --policy policies/default_policy.yaml \
    --input inputs.json
```

Output:

```json
{
  "status": "success",
  "output": {"content": "hello from workspace"},
  "errors": [],
  "steps_executed": 1,
  "audit": [...]
}
```

---

## What GuardBunny Protects Against

- **Prompt injection**: The LLM cannot inject arbitrary shell commands
- **Path traversal**: `../../etc/passwd` resolves outside the allowed root and is denied
- **Network exfiltration**: Only hosts in `allowed_hosts` can be reached
- **Shell escape**: Shell binaries and interpreter code-execution flags are hard-blocked
- **Interpreter escape**: `python -c`, `node -e`, `perl -e`, etc. are hard-blocked
- **Unchecked loops**: Repeat loops are capped and re-authorized every iteration
- **Implicit authorization**: Every step is independently authorized before execution

## What GuardBunny Does NOT Protect Against

- **argv content in process.run_allowed**: An allowlisted binary like `/usr/bin/grep` can be given a path argument that reads outside the workspace. Future work: per-binary argv restriction rules.
- **SSRF via allowed hosts**: If an allowlisted host acts as a proxy, GuardBunny cannot see the second hop.
- **Symlink attacks**: The policy resolves paths at check time; the executor resolves again at read time. A symlink swap between these two moments is a TOCTOU window.
- **Sandbox escape**: GuardBunny does not use OS-level sandboxing (seccomp, namespaces). A future integration point for these is marked with TODO in the source.
- **Malicious content in file output**: GuardBunny does not inspect the semantic content of files it reads or writes.

See [docs/threat-model.md](docs/threat-model.md) for the full threat model.

---

## Repository Layout

```text
guardbunny/          Python package — the secure runtime
  models.py          Core data types (IRStep, PolicyDecision, RuntimeState, …)
  parser.py          .gb YAML → WorkflowSpec AST
  ir.py              AST + runtime state → typed IRStep
  conditions.py      Restricted boolean expression evaluator (no eval())
  policy.py          YAML-backed policy engine (default deny)
  executor.py        Typed action execution (no shell=True)
  audit.py           Append-only per-run audit log
  runtime.py         Orchestrator: parse → IR → policy → execute → audit
  cli.py             CLI entry point
policies/            Example policy YAML files
examples/            Example .gb workflow files
tests/               pytest test suite
docs/                Architecture, threat model, DSL reference, security notes
legacy/              Original ProLang prototype (preserved, not authoritative)
```
