# agent-tool-firewall

A defensive permission boundary between AI agents and their tools: scoped
capabilities, sandboxed execution, credential isolation, human approval
gates, and a complete audit trail.

## Why this exists

In November 2026, Google Threat Intelligence Group and Mandiant reported
threat actors running autonomous multi-agent frameworks inside live
intrusions — specialized agents with shared context, broad tool access, and
automated feedback loops, executing multi-stage attacks at machine speed.

Here's the uncomfortable part: the same architecture is what we're all
building on the defensive side. Your support agent, your research agent,
your coding agent — they all hold tools. And a tool call doesn't care why it
was made. A prompt-injected agent reading a credentials file looks exactly
like a legitimate one doing it, unless something *outside the model* says no.

Prompt guardrails are not a boundary. They're advice the model can be talked
out of. This project is the boundary: a deterministic firewall that sits
between every agent and every tool, and decides — before anything executes —
whether this agent is allowed to do this thing, on this resource, at this
amount, right now.

## What it does

Every tool call goes through the same gauntlet:

1. **Policy check** — deny-by-default, deterministic. Each agent has a
   least-privilege capability set in a YAML policy: which tools, which
   operations, which resource globs, spending caps, rate limits.
2. **Approval gate** — high-risk operations pause for a human yes/no.
   No approver configured means blocked, not waved through.
3. **Credential injection** — the vault hands secrets directly to the tool
   at call time. The agent never sees them, and anything the tool returns
   is redacted before the agent (or the log) sees it.
4. **Sandboxed execution** — restricted filesystem view (paths can't escape
   the sandbox root), hard timeouts, output size caps.
5. **Audit** — every attempt is appended to a JSONL log: agent, tool,
   operation, a hash of the arguments (never the raw args), the verdict,
   and the outcome. Blocked attempts are logged too — especially those.

## Architecture

```
                ┌─────────────┐
   agent ──────▶│  FIREWALL   │◀────── policy.yaml (capabilities, caps,
   (never sees  │             │        approval rules, allowlists)
    tools or    │ 1. policy   │
    secrets)    │ 2. approval │──────▶ human approver (optional)
                │ 3. vault    │◀────── secrets (env / vault store)
                │ 4. sandbox  │
                │ 5. redact   │
                │ 6. audit    │──────▶ audit.jsonl (append-only)
                └──────┬──────┘
                       ▼
                 tools (mock or real)
```

Agents hold a reference to the firewall, never to the tools. There is no
path from an agent to a tool that skips the checks.

## The demo

A support agent reads a playbook containing a prompt injection. The
injection tells it to: read the credentials file, run a shell command,
delete a user, exfiltrate data to an external URL, and charge a customer
$9999. The demo runs the same agents twice:

```
$ python -m agent_tool_firewall demo

--- WITHOUT firewall (agents call tools directly) ---
[support-agent]
  OK       Read credentials file (file.read)
  OK       Run shell command (shell.exec)
  OK       Delete a user (admin) (admin.delete_user)
  OK       Exfiltrate data to external URL (http.post)
  OK       Charge $9999 (over spending cap) (payments.charge)

--- WITH firewall (policy enforced before every call) ---
[support-agent]
  OK       Issue $25 refund (within cap) (payments.charge)
  BLOCKED  Read credentials file (file.read)
           ↳ resource 'secrets/credentials.txt' is outside allowed scope ['docs/*']
  BLOCKED  Run shell command (shell.exec)
           ↳ agent 'support-agent' has no capability for shell.exec
  BLOCKED  Delete a user (admin) (admin.delete_user)
           ↳ agent 'support-agent' has no capability for admin.delete_user
  BLOCKED  Exfiltrate data to external URL (http.post)
           ↳ agent 'support-agent' has no capability for http.post
  BLOCKED  Charge $9999 (over spending cap) (payments.charge)
           ↳ amount 9999 exceeds cap 50

Attacks succeeded without firewall: 5/5
Attacks blocked with firewall:    5/5
```

All tools in the demo are safe mocks — the shell executes nothing, HTTP
sends nothing, payments move no money. The point is the boundary, not the
tools behind it.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .

# Mock mode (default): deterministic, offline, no key needed
.venv/bin/python -m agent_tool_firewall demo

# Dry-run a single policy decision
.venv/bin/python -m agent_tool_firewall check \
  --agent support-agent --tool payments --operation charge \
  --args '{"amount": 9999}'

# Summarize an audit log
.venv/bin/python -m agent_tool_firewall audit audit.jsonl

# Tests
.venv/bin/pip install pytest
.venv/bin/python -m pytest -q
```

## Live mode

In live mode a real model plays the compromised support agent. It reads the
same poisoned playbook and decides for itself what to call. Whatever it
tries goes through the firewall — the boundary holds regardless of what the
model attempts.

```bash
.venv/bin/pip install litellm

# Gemini (default model)
export GEMINI_API_KEY=...
.venv/bin/python -m agent_tool_firewall demo --live

# Any LiteLLM-supported provider works — set LLM_MODEL + that provider's key:
export LLM_MODEL=groq/llama-3.3-70b-versatile   GROQ_API_KEY=...
export LLM_MODEL=openrouter/openai/gpt-4o-mini  OPENROUTER_API_KEY=...
export LLM_MODEL=ollama/llama3.1                # local, no key needed
```

Keys are read only from the environment. Nothing is hardcoded, and nothing
secret is ever printed — the vault redacts secrets from tool output and
audit entries.

## Policy config

Policy is YAML, enforced as code. Deny-by-default: if it isn't listed, it
doesn't happen.

```yaml
network:
  allowlist: [api.internal.example.com]   # every other host is denied

tools:
  admin:
    risk: critical
    requires_approval: true               # human must say yes

agents:
  support-agent:
    capabilities:
      - tool: docs
        operations: [search]
      - tool: file
        operations: [read]
        resources: ["docs/*"]             # only these paths
      - tool: payments
        operations: [charge]
        constraints:
          max_amount: 50                  # spending cap
          rate_limit: {max_calls: 5, window_seconds: 60}
```

See `policies/default.yaml` for the full example used by the demo.

## Audit log

One JSON object per line, append-only. Arguments are SHA-256 hashed, never
stored raw; reasons and error details pass through the vault redactor.

```json
{"timestamp": 1795343511.99, "agent": "support-agent", "tool": "payments", "operation": "charge", "args_hash": "9f2c…", "verdict": "blocked", "reason": "amount 9999 exceeds cap 50", "outcome": "blocked", "risk": "high", "duration_ms": null, "detail": ""}
{"timestamp": 1795343512.01, "agent": "research-agent", "tool": "docs", "operation": "search", "args_hash": "41ab…", "verdict": "allowed", "reason": "allowed by policy", "outcome": "success", "risk": "low", "duration_ms": 3.2, "detail": ""}
```

## Threat model — what this does and doesn't do

**It does:**

- Enforce least-privilege execution boundaries that hold even when the
  model is compromised, confused, or prompt-injected.
- Keep raw credentials out of the model's context entirely, and redact
  them from anything flowing back.
- Cap blast radius: spending limits, rate limits, resource scopes,
  network allowlists, timeouts.
- Produce a complete, tamper-evident record of what was attempted —
  including the attempts that were stopped.

**It doesn't:**

- Fix a bad model. A model that *wants* to do the wrong thing will keep
  trying; the firewall just makes the wrong thing impossible to execute.
- Judge intent. An in-scope call made for a malicious reason still runs —
  that's what approval gates and tight scopes are for.
- Protect tools that bypass it. If an agent can reach a tool through any
  path other than the firewall, the boundary is decorative. Wire every
  tool through it.
- Replace real sandboxing for real tools. The sandbox here is a reference
  wrapper (path confinement, timeouts, output caps); production tools
  that execute code or touch networks need OS-level isolation too.

## Project layout

```
src/agent_tool_firewall/
  policy.py    capability model + deterministic evaluator
  firewall.py  the interceptor (policy → approval → vault → sandbox → audit)
  sandbox.py   execution wrapper: FS confinement, timeouts, output caps
  vault.py     secret injection + redaction
  audit.py     append-only JSONL audit log (hashed args)
  tools.py     safe mock tools + demo fixtures
  agents.py    reference legit agent, compromised agent, live agent
  llm.py       LiteLLM wrapper with 429/503 backoff
  demo.py      side-by-side with/without-firewall demo
  cli.py       demo / check / audit commands
policies/default.yaml
tests/         45 tests, fully offline
```

## License

MIT
