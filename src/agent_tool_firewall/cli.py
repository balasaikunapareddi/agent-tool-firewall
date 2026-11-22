"""Command-line interface.

    python -m agent_tool_firewall demo              # side-by-side demo (mock)
    python -m agent_tool_firewall demo --live       # real model plays the agent
    python -m agent_tool_firewall check ...         # dry-run one policy decision
    python -m agent_tool_firewall audit <file>      # summarize an audit log
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import DEFAULT_POLICY_PATH, main_demo
from .policy import Policy, PolicyEvaluator


def _cmd_demo(args: argparse.Namespace) -> int:
    if args.live:
        return _run_live_demo(args)
    return main_demo(args.policy)


def _run_live_demo(args: argparse.Namespace) -> int:
    import tempfile

    from .agents import LiveCompromisedAgent
    from .audit import AuditLog
    from .firewall import ToolFirewall
    from .sandbox import Sandbox
    from .tools import FAKE_DB_PASSWORD, FAKE_PAYMENTS_KEY, MockWorld, build_mock_registry, seed_workspace
    from .vault import Vault

    policy = Policy.from_yaml(args.policy)
    base = Path(tempfile.mkdtemp(prefix="tool-firewall-live-"))
    seed_workspace(base)
    world = MockWorld()
    sandbox = Sandbox(
        root=base,
        timeout_seconds=policy.sandbox.timeout_seconds,
        max_output_chars=policy.sandbox.max_output_chars,
    )
    vault = Vault({"payments_api_key": FAKE_PAYMENTS_KEY, "db_password": FAKE_DB_PASSWORD})
    registry = build_mock_registry(world)
    audit = AuditLog(path=base / "audit.jsonl", redactor=vault.redact)
    firewall = ToolFirewall(policy, registry, vault, audit, sandbox)

    agent = LiveCompromisedAgent()
    print(f"Live mode: model={agent.model} (set LLM_MODEL to change)")
    run = agent.run(firewall, registry.describe())
    for step in run.steps:
        mark = "OK  " if step.ok else ("BLOCKED" if step.blocked else "FAIL")
        print(f"  {mark:8} {step.label} — {step.detail}")
    print(f"\nModel made {len(run.steps)} tool calls; {run.blocked} blocked by the firewall.")
    print(f"Audit log: {base / 'audit.jsonl'}")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    policy = Policy.from_yaml(args.policy)
    evaluator = PolicyEvaluator(policy)
    try:
        call_args = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError as exc:
        print(f"--args is not valid JSON: {exc}", file=sys.stderr)
        return 2
    verdict = evaluator.evaluate(args.agent, args.tool, args.operation, call_args)
    print(f"allowed: {verdict.allowed}")
    print(f"reason:  {verdict.reason}")
    print(f"risk:    {verdict.risk.value}")
    print(f"approval required: {verdict.requires_approval}")
    return 0 if verdict.allowed else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2
    counts: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        counts[entry["outcome"]] = counts.get(entry["outcome"], 0) + 1
        print(
            f"{entry['agent']:16} {entry['tool']}.{entry['operation']:12} "
            f"{entry['verdict']:18} {entry['outcome']:8} {entry['reason']}"
        )
    print(f"\nTotals: {counts}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-tool-firewall")
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY_PATH),
        help="path to policy YAML (default: policies/default.yaml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_demo = sub.add_parser("demo", help="run the side-by-side demo")
    p_demo.add_argument("--live", action="store_true", help="real model plays the compromised agent")
    p_demo.set_defaults(func=_cmd_demo)

    p_check = sub.add_parser("check", help="dry-run a single policy decision")
    p_check.add_argument("--agent", required=True)
    p_check.add_argument("--tool", required=True)
    p_check.add_argument("--operation", required=True)
    p_check.add_argument("--args", default="", help="JSON object of call arguments")
    p_check.set_defaults(func=_cmd_check)

    p_audit = sub.add_parser("audit", help="summarize an audit log file")
    p_audit.add_argument("file")
    p_audit.set_defaults(func=_cmd_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
