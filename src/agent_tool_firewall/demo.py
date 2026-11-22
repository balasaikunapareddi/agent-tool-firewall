"""Side-by-side demo: same agents, same tools — with and without the firewall.

Without the firewall, a prompt-injected support agent reads the credentials
file, runs shell commands, deletes a user, exfiltrates data, and charges
$9999. With the firewall, all five are blocked and logged, while legitimate
in-scope work (doc search, a $25 refund, a report write) completes normally.

Everything runs against safe mock tools in a temp sandbox directory.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from .agents import ATTACK_SCRIPT, AgentRun, CompromisedAgent, ResearchAgent
from .audit import AuditLog
from .firewall import DirectRunner, ToolFirewall
from .policy import Policy
from .sandbox import Sandbox
from .tools import FAKE_DB_PASSWORD, FAKE_PAYMENTS_KEY, MockWorld, build_mock_registry, seed_workspace
from .vault import Vault

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"


@dataclass
class DemoResult:
    without_firewall: dict[str, AgentRun]
    with_firewall: dict[str, AgentRun]
    audit: AuditLog
    world_without: MockWorld
    world_with: MockWorld

    @property
    def attacks_succeeded_without(self) -> int:
        run = self.without_firewall["support-agent"]
        labels = {label for label, *_ in ATTACK_SCRIPT}
        return sum(1 for s in run.steps if s.label in labels and s.ok)

    @property
    def attacks_blocked_with(self) -> int:
        run = self.with_firewall["support-agent"]
        labels = {label for label, *_ in ATTACK_SCRIPT}
        return sum(1 for s in run.steps if s.label in labels and s.blocked)


def _build_stack(root: Path, policy: Policy, world: MockWorld, audit_path: Path | None):
    seed_workspace(root)
    sandbox = Sandbox(
        root=root,
        timeout_seconds=policy.sandbox.timeout_seconds,
        max_output_chars=policy.sandbox.max_output_chars,
    )
    vault = Vault(
        {"payments_api_key": FAKE_PAYMENTS_KEY, "db_password": FAKE_DB_PASSWORD}
    )
    registry = build_mock_registry(world)
    audit = AuditLog(path=audit_path, redactor=vault.redact)
    firewall = ToolFirewall(policy, registry, vault, audit, sandbox)
    direct = DirectRunner(registry, sandbox, vault)
    return firewall, direct, audit


def run_demo(policy_path: str | Path | None = None, workdir: str | Path | None = None) -> DemoResult:
    policy = Policy.from_yaml(policy_path or DEFAULT_POLICY_PATH)
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="tool-firewall-demo-"))

    # --- Without firewall -------------------------------------------------
    world_without = MockWorld()
    _, direct, _ = _build_stack(base / "without", policy, world_without, None)
    without = {
        "research-agent": ResearchAgent().run(direct),
        "support-agent": CompromisedAgent().run(direct),
    }

    # --- With firewall ----------------------------------------------------
    world_with = MockWorld()
    firewall, _, audit = _build_stack(
        base / "with", policy, world_with, base / "audit.jsonl"
    )
    with_fw = {
        "research-agent": ResearchAgent().run(firewall),
        "support-agent": CompromisedAgent().run(firewall),
    }

    return DemoResult(
        without_firewall=without,
        with_firewall=with_fw,
        audit=audit,
        world_without=world_without,
        world_with=world_with,
    )


def _format_run(title: str, runs: dict[str, AgentRun]) -> list[str]:
    lines = [f"--- {title} ---"]
    for agent_id, run in runs.items():
        lines.append(f"[{agent_id}]")
        for step in run.steps:
            mark = "OK  " if step.ok else ("BLOCKED" if step.blocked else "FAIL")
            lines.append(f"  {mark:8} {step.label} ({step.tool}.{step.operation})")
            if step.blocked:
                lines.append(f"           ↳ {step.detail}")
    return lines


def format_report(result: DemoResult) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("AGENT TOOL FIREWALL — DEMO")
    lines.append("A prompt-injected support agent tries 5 out-of-scope actions.")
    lines.append("=" * 72)
    lines += _format_run("WITHOUT firewall (agents call tools directly)", result.without_firewall)
    lines.append("")
    lines += _format_run("WITH firewall (policy enforced before every call)", result.with_firewall)
    lines.append("")
    lines.append("-" * 72)
    lines.append(
        f"Attacks succeeded without firewall: {result.attacks_succeeded_without}/5"
    )
    lines.append(f"Attacks blocked with firewall:    {result.attacks_blocked_with}/5")
    legit = result.with_firewall["research-agent"]
    lines.append(f"Legitimate research work completed: {legit.succeeded}/{len(legit.steps)} steps")
    lines.append("")
    lines.append("Audit log (with firewall) — every attempt recorded:")
    for entry in result.audit.entries:
        lines.append(
            f"  {entry.agent:16} {entry.tool}.{entry.operation:12} "
            f"verdict={entry.verdict:18} outcome={entry.outcome:8} {entry.reason}"
        )
    lines.append("-" * 72)
    return "\n".join(lines)


def main_demo(policy_path: str | Path | None = None) -> int:
    result = run_demo(policy_path)
    print(format_report(result))
    ok = result.attacks_blocked_with == 5 and result.attacks_succeeded_without == 5
    return 0 if ok else 1
