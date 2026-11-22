"""The tool-permission firewall.

Every agent tool call passes through :meth:`ToolFirewall.call`:

1. **Policy check** — deterministic, deny-by-default (see policy.py).
2. **Approval gate** — high-risk operations pause for a human decision.
3. **Credential injection** — the vault hands secrets straight to the tool;
   the agent never sees them.
4. **Sandboxed execution** — timeout, output cap, restricted filesystem.
5. **Redaction** — secrets are stripped from tool output before the agent
   sees it.
6. **Audit** — every attempt is logged, blocked or not.

Agents hold a reference to the firewall, never to the tools themselves.
That is the whole point: there is no path from an agent to a tool that
skips the checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .audit import AuditLog
from .policy import Policy, PolicyEvaluator
from .sandbox import Sandbox
from .tools import ToolRegistry
from .vault import Vault

# approver(agent, tool, operation, args) -> bool. Returning False (or having
# no approver at all) blocks the call.
Approver = Callable[[str, str, str, dict[str, Any]], bool]


@dataclass
class CallResult:
    ok: bool
    output: Any = None
    error: str = ""
    blocked: bool = False
    verdict: str = ""  # allowed | blocked | approval_required | approval_denied
    reason: str = ""


class ToolFirewall:
    def __init__(
        self,
        policy: Policy,
        registry: ToolRegistry,
        vault: Vault,
        audit: AuditLog,
        sandbox: Sandbox,
        approver: Approver | None = None,
    ):
        self.policy = policy
        self.evaluator = PolicyEvaluator(policy)
        self.registry = registry
        self.vault = vault
        self.audit = audit
        self.sandbox = sandbox
        self.approver = approver

    def call(
        self, agent_id: str, tool: str, operation: str, args: dict[str, Any] | None = None
    ) -> CallResult:
        args = dict(args or {})
        verdict = self.evaluator.evaluate(agent_id, tool, operation, args)
        risk = verdict.risk.value

        if verdict.blocked:
            self.audit.record(
                agent=agent_id,
                tool=tool,
                operation=operation,
                args=args,
                verdict="blocked",
                reason=verdict.reason,
                outcome="blocked",
                risk=risk,
            )
            return CallResult(
                ok=False,
                error=f"blocked by firewall: {verdict.reason}",
                blocked=True,
                verdict="blocked",
                reason=verdict.reason,
            )

        if verdict.requires_approval:
            approved = bool(self.approver and self.approver(agent_id, tool, operation, args))
            if not approved:
                label = "approval_denied" if self.approver else "approval_required"
                reason = (
                    "human approver denied the call"
                    if self.approver
                    else "operation requires human approval; no approver configured"
                )
                self.audit.record(
                    agent=agent_id,
                    tool=tool,
                    operation=operation,
                    args=args,
                    verdict=label,
                    reason=reason,
                    outcome="blocked",
                    risk=risk,
                )
                return CallResult(
                    ok=False,
                    error=f"blocked by firewall: {reason}",
                    blocked=True,
                    verdict=label,
                    reason=reason,
                )

        handler = self.registry.handler(tool, operation)
        if handler is None:
            reason = f"tool {tool}.{operation} is not registered"
            self.audit.record(
                agent=agent_id,
                tool=tool,
                operation=operation,
                args=args,
                verdict="blocked",
                reason=reason,
                outcome="blocked",
                risk=risk,
            )
            return CallResult(
                ok=False, error=reason, blocked=True, verdict="blocked", reason=reason
            )

        credentials = self.vault.inject(self.registry.required_credentials(tool))
        result = self.sandbox.execute(handler, args, credentials=credentials)
        self.evaluator.record_call(agent_id, tool)

        if not result.ok:
            outcome = "timeout" if result.timed_out else "error"
            self.audit.record(
                agent=agent_id,
                tool=tool,
                operation=operation,
                args=args,
                verdict="allowed",
                reason=verdict.reason,
                outcome=outcome,
                risk=risk,
                duration_ms=result.duration_ms,
                detail=self.vault.redact(result.error),
            )
            return CallResult(
                ok=False,
                error=self.vault.redact(result.error),
                verdict="allowed",
                reason=verdict.reason,
            )

        safe_output = self.vault.redact(result.output)
        self.audit.record(
            agent=agent_id,
            tool=tool,
            operation=operation,
            args=args,
            verdict="allowed",
            reason=verdict.reason,
            outcome="success",
            risk=risk,
            duration_ms=result.duration_ms,
        )
        return CallResult(
            ok=True, output=safe_output, verdict="allowed", reason=verdict.reason
        )


class DirectRunner:
    """No firewall: agents call tools directly. Exists ONLY so the demo can
    show what happens without the boundary. Never use this in production."""

    def __init__(self, registry: ToolRegistry, sandbox: Sandbox, vault: Vault):
        self.registry = registry
        self.sandbox = sandbox
        self.vault = vault

    def call(
        self, agent_id: str, tool: str, operation: str, args: dict[str, Any] | None = None
    ) -> CallResult:
        args = dict(args or {})
        handler = self.registry.handler(tool, operation)
        if handler is None:
            return CallResult(ok=False, error=f"tool {tool}.{operation} is not registered")
        credentials = self.vault.inject(self.registry.required_credentials(tool))
        result = self.sandbox.execute(handler, args, credentials=credentials)
        # No redaction, no audit, no policy — the agent sees everything.
        return CallResult(
            ok=result.ok,
            output=result.output,
            error=result.error,
            verdict="unfiltered",
            reason="no firewall",
        )
