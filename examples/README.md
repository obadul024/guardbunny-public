# GuardBunny Examples

GuardBunny runs two files together: a **workflow** (`.gb`) and a **policy** (`.yaml`).

- The **workflow** describes what to do — read a file, call an API, run a command.
- The **policy** decides what is allowed to run — which paths, which hosts, which binaries.

Every action in the workflow is checked against the policy before it executes. If it's not explicitly allowed, it's denied.

```
workflow.gb  +  policy.yaml  →  GuardBunny  →  result + audit log
```

---

## Setup

```bash
pip install -e ".[dev]"
mkdir -p /tmp/guardbunny
echo "hello world" > /tmp/guardbunny/test.txt
```

---

## How They Work Together

Here's the simplest possible example — reading a file.

**Workflow** (`examples/safe_read.gb`):
```yaml
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

**Policy** (`policies/default_policy.yaml`) — the relevant part:
```yaml
allowed_actions:
  - file.read

file_read:
  allowed_roots:
    - /tmp/guardbunny
```

The workflow says: *read this file*. The policy says: *file.read is allowed, but only inside `/tmp/guardbunny`*. GuardBunny checks the path against the policy before the executor ever touches the file.

**Run it:**
```bash
echo '{"file_path": "/tmp/guardbunny/test.txt"}' > input.json
guardbunny examples/safe_read.gb --policy policies/default_policy.yaml --input input.json
```

**Now try a path outside the allowed root — same workflow, same policy, different input:**
```bash
echo '{"file_path": "/etc/passwd"}' > input.json
guardbunny examples/safe_read.gb --policy policies/default_policy.yaml --input input.json
```

Denied. The audit log shows exactly why.

---

## File Actions

### Write a file

**Workflow** (`examples/safe_write.gb`):
```yaml
steps:
  - id: write_file
    do:
      action: file.write
      args:
        path: "${input.file_path}"
        content: "${input.content}"
    emit:
      bytes_written: "${steps.write_file.result.bytes_written}"
```

**Policy controls:**
```yaml
file_write:
  enabled: true
  allowed_roots:
    - /tmp/guardbunny
  max_bytes: 524288   # 512 KB
```

```bash
echo '{"file_path": "/tmp/guardbunny/out.txt", "content": "hello"}' > input.json
guardbunny examples/safe_write.gb --policy policies/default_policy.yaml --input input.json
```

**What the policy enforces:**
- Path must resolve inside `allowed_roots` — symlinks and `../` traversal are resolved before the check
- Content must be under `max_bytes`
- `file.write` must be listed in `allowed_actions` — remove it and every write is denied instantly

**Write outside the allowed root** (`examples/deny_write_outside_test1.gb`):
```yaml
steps:
  - id: write_file
    do:
      action: file.write
      args:
        path: /tmp/not_allowed/out.txt
        content: "should fail"
```
```bash
guardbunny examples/deny_write_outside_test1.gb --policy policies/default_policy.yaml
```
Denied. `/tmp/not_allowed` is not under any `allowed_roots`.

**Write too much** (`examples/deny_write_big_test1.gb`) — content exceeds `max_bytes`:
```bash
guardbunny examples/deny_write_big_test1.gb --policy policies/default_policy.yaml
```
Denied. Size limit enforced before execution.

---

## HTTP Actions

### Fetch a URL

**Workflow** (`examples/safe_http_fetch.gb`):
```yaml
steps:
  - id: fetch
    do:
      action: http.fetch
      args:
        url: "${input.url}"
        method: GET
    emit:
      status_code: "${steps.fetch.result.status_code}"
      body: "${steps.fetch.result.body}"
```

**Policy controls:**
```yaml
http_fetch:
  allowed_hosts:
    - example.com
    - api.example.com
    - "*.example.com"
  allowed_methods:
    - GET
    - POST
  timeout_sec: 30
  max_output_bytes: 65536
```

```bash
echo '{"url": "https://example.com"}' > input.json
guardbunny examples/safe_http_fetch.gb --policy policies/default_policy.yaml --input input.json
```

**Allowed vs denied — side by side:**

`examples/http_ok_test1.gb` fetches `https://example.com` → **allowed** (in `allowed_hosts`)

`examples/http_bad_host_test1.gb` fetches `https://google.com` → **denied** (not in `allowed_hosts`)

```bash
guardbunny examples/http_ok_test1.gb --policy policies/default_policy.yaml      # ALLOWED
guardbunny examples/http_bad_host_test1.gb --policy policies/default_policy.yaml # DENIED
```

The workflow files are identical in structure. The policy is what makes one succeed and the other fail.

---

## Process Execution

This is the highest-risk action type. GuardBunny enforces multiple layers:

1. Binary must be in `allowed_binaries`
2. Shell binaries (`bash`, `sh`, `zsh`, etc.) are **permanently blocked** — no policy can enable them
3. Interpreter inline flags (`-c`, `-m`, `-e`) are **permanently blocked**
4. Arguments are checked against per-binary rules (`allowed_flags`, `allowed_file_roots`)

**Policy controls:**
```yaml
process_run:
  allowed_binaries:
    - /usr/bin/grep
    - /usr/bin/wc
    - /usr/bin/head

process_run_rules:
  /usr/bin/grep:
    allowed_flags: ["-i", "-n", "-F", "-E", "-e"]
    allowed_file_roots:
      - /tmp/guardbunny
```

### Shell escape attempt — always denied

**`examples/denied_bash_escape.gb`:**
```yaml
steps:
  - id: attempt_shell_escape
    do:
      action: process.run_allowed
      args:
        binary: /bin/bash
        argv: ["-c", "cat /etc/passwd"]
```

```bash
guardbunny examples/denied_bash_escape.gb --policy policies/default_policy.yaml
```

Denied with `SHELL_BINARY_DENIED`. The executor is never called. The audit log records the attempt.

**`examples/deny_bash_test1.gb`** is the same pattern — any shell binary, any args, always denied.

### Interpreter inline code — always denied

**`examples/deny_python_c_test1.gb`:**
```yaml
args:
  binary: python3
  argv: ["-c", "print('owned')"]
```

```bash
guardbunny examples/deny_python_c_test1.gb --policy policies/default_policy.yaml
```

Denied. The `-c` flag is hard-blocked on all interpreters regardless of policy.

### Binary not in allowlist

**`examples/deny_binary_not_allowed_test1.gb`** — tries `/usr/bin/cat`, which is not in `allowed_binaries`:

```bash
guardbunny examples/deny_binary_not_allowed_test1.gb --policy policies/default_policy.yaml
```

Denied. Being a legitimate system binary is not enough — it must be explicitly listed.

### Allowlisted binary, disallowed file target

**`examples/deny_binary_args.gb`** — uses `/usr/bin/grep` (which IS allowlisted) but targets `/etc/passwd` (outside `allowed_file_roots`):

```yaml
args:
  binary: /usr/bin/grep
  argv:
    - root
    - /etc/passwd
```

```bash
guardbunny examples/deny_binary_args.gb --policy policies/default_policy.yaml
```

Denied. The binary is allowed but the file operand falls outside `/tmp/guardbunny`. Allowlisting a binary does not give it unrestricted file access.

---

## Conditional Execution

**`examples/condition_true_test1.gb`** — branches based on an input value. The policy is re-checked for every branch step that actually executes.

```yaml
steps:
  - id: branch
    condition:
      test: input.flag == True
      then:
        - id: yes_write
          do:
            action: file.write
            args:
              path: /tmp/guardbunny/cond_yes.txt
              content: "yes"
          emit:
            branch_taken: "then"
      else:
        - id: no_write
          do:
            action: file.write
            args:
              path: /tmp/guardbunny/cond_no.txt
              content: "no"
          emit:
            branch_taken: "else"
```

```bash
echo '{"flag": true}' > input.json
guardbunny examples/condition_true_test1.gb --policy policies/default_policy.yaml --input input.json
```

The `then` branch executes, the `else` branch does not. Only the steps that actually run are checked against the policy.

---

## Loops

**`examples/repeat_read_test1.gb`** — reads the same file 3 times, collecting results. The policy is re-checked on every iteration.

```yaml
steps:
  - id: loop_read
    repeat:
      times: 3
      do:
        action: file.read
        args:
          path: /tmp/guardbunny/test.txt
    emit:
      reads:
        merge: append
        value: "${result.content}"
```

```bash
guardbunny examples/repeat_read_test1.gb --policy policies/default_policy.yaml
```

`reads` comes back as an array of 3 strings. The audit log shows 3 separate policy decisions — one per iteration. Use `${vars.loop.index}` inside the loop to vary the path per iteration.

---

## Interpolation Reference

| Expression | Resolves to |
|---|---|
| `${input.key}` | Caller-provided input field |
| `${steps.step_id.result.key}` | Result field from a completed step |
| `${result.key}` | Shorthand for current step result (inside `emit` only) |
| `${vars.loop.index}` | Current iteration index inside a `repeat` loop |

---

## Policy Reference

All examples use `policies/default_policy.yaml`. The three policy files in the repo:

| Policy file | What it allows |
|---|---|
| `default_policy.yaml` | Read + write + HTTP + process, all scoped to `/tmp/guardbunny` |
| `default_strict_policy.yaml` | Tighter version of the above |
| `read_only_policy.yaml` | `file.read` only, no writes, no HTTP, no process |

To see how policy changes behaviour, run any example with `read_only_policy.yaml` instead — anything other than a read will be denied.
