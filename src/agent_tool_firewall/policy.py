"""Policy model and deterministic evaluator.

The policy is the contract: it says, per agent, exactly which tools may be
used, which operations on them, on which resources, and under which
constraints (spending caps, rate limits, human approval). Everything not
explicitly allowed is denied. Evaluation is pure and deterministic — no
model calls, no heuristics — so a verdict can always be explained.
"""

from __future__ import annotations

import fnmatch
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RateLimit:
    max_calls: int
    window_seconds: float


@dataclass
class Constraints:
    max_amount: float | None = None
    rate_limit: RateLimit | None = None
    allowed_hosts: list[str] | None = None  # per-capability network allowlist


@dataclass
class Capability:
    tool: str
    operations: list[str]
    resources: list[str] = field(default_factory=list)  # globs; empty = any
    constraints: Constraints = field(default_factory=Constraints)
    requires_approval: bool = False


@dataclass
class ToolPolicy:
    risk: RiskTier = RiskTier.MEDIUM
    requires_approval: bool = False


@dataclass
class AgentPolicy:
    agent_id: str
    description: str = ""
    capabilities: list[Capability] = field(default_factory=list)

    def capability_for(self, tool: str, operation: str) -> Capability | None:
        for cap in self.capabilities:
            if cap.tool == tool and operation in cap.operations:
                return cap
        return None


@dataclass
class SandboxPolicy:
    root: str = "./sandbox-data"
    timeout_seconds: float = 5.0
    max_output_chars: int = 4000


@dataclass
class Policy:
    agents: dict[str, AgentPolicy]
    tools: dict[str, ToolPolicy]
    network_allowlist: list[str] = field(default_factory=list)
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        tools: dict[str, ToolPolicy] = {}
        for name, cfg in (data.get("tools") or {}).items():
            cfg = cfg or {}
            tools[name] = ToolPolicy(
                risk=RiskTier(str(cfg.get("risk", "medium")).lower()),
                requires_approval=bool(cfg.get("requires_approval", False)),
            )

        agents: dict[str, AgentPolicy] = {}
        for agent_id, cfg in (data.get("agents") or {}).items():
            cfg = cfg or {}
            caps: list[Capability] = []
            for raw in cfg.get("capabilities") or []:
                cons_raw = raw.get("constraints") or {}
                rl_raw = cons_raw.get("rate_limit")
                caps.append(
                    Capability(
                        tool=raw["tool"],
                        operations=list(raw.get("operations") or []),
                        resources=list(raw.get("resources") or []),
                        constraints=Constraints(
                            max_amount=cons_raw.get("max_amount"),
                            rate_limit=(
                                RateLimit(
                                    max_calls=int(rl_raw["max_calls"]),
                                    window_seconds=float(rl_raw["window_seconds"]),
                                )
                                if rl_raw
                                else None
                            ),
                            allowed_hosts=cons_raw.get("allowed_hosts"),
                        ),
                        requires_approval=bool(raw.get("requires_approval", False)),
                    )
                )
            agents[agent_id] = AgentPolicy(
                agent_id=agent_id,
                description=str(cfg.get("description", "")),
                capabilities=caps,
            )

        sb = data.get("sandbox") or {}
        return cls(
            agents=agents,
            tools=tools,
            network_allowlist=list((data.get("network") or {}).get("allowlist") or []),
            sandbox=SandboxPolicy(
                root=str(sb.get("root", "./sandbox-data")),
                timeout_seconds=float(sb.get("timeout_seconds", 5.0)),
                max_output_chars=int(sb.get("max_output_chars", 4000)),
            ),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})


@dataclass
class Verdict:
    allowed: bool
    reason: str
    requires_approval: bool = False
    risk: RiskTier = RiskTier.MEDIUM

    @property
    def blocked(self) -> bool:
        return not self.allowed


class PolicyEvaluator:
    """Evaluates (agent, tool, operation, args) against a Policy.

    Deny-by-default. Checks run in a fixed order so the reason for a denial
    is stable and auditable:

    1. agent known?  2. tool+operation granted?  3. resource in scope?
    4. amount within cap?  5. network host allowlisted?  6. rate limit?
    7. approval required?
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self._call_times: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def evaluate(
        self, agent_id: str, tool: str, operation: str, args: dict[str, Any]
    ) -> Verdict:
        tool_policy = self.policy.tools.get(tool, ToolPolicy())
        risk = tool_policy.risk

        agent = self.policy.agents.get(agent_id)
        if agent is None:
            return Verdict(False, f"unknown agent '{agent_id}'", risk=risk)

        cap = agent.capability_for(tool, operation)
        if cap is None:
            return Verdict(
                False,
                f"agent '{agent_id}' has no capability for {tool}.{operation}",
                risk=risk,
            )

        # Resource scope (e.g. file paths).
        if cap.resources:
            resource = str(args.get("path") or args.get("resource") or "")
            if not any(fnmatch.fnmatch(resource, pat) for pat in cap.resources):
                return Verdict(
                    False,
                    f"resource '{resource}' is outside allowed scope {cap.resources}",
                    risk=risk,
                )

        # Spending cap.
        if cap.constraints.max_amount is not None and "amount" in args:
            try:
                amount = float(args["amount"])
            except (TypeError, ValueError):
                return Verdict(False, "amount is not a number", risk=risk)
            if amount > cap.constraints.max_amount:
                return Verdict(
                    False,
                    f"amount {amount:g} exceeds cap {cap.constraints.max_amount:g}",
                    risk=risk,
                )

        # Network allowlist for URL-bearing calls.
        url = args.get("url")
        if url:
            host = urlparse(str(url)).hostname or ""
            allowed_hosts = cap.constraints.allowed_hosts
            if allowed_hosts is None:
                allowed_hosts = self.policy.network_allowlist
            if host not in allowed_hosts:
                return Verdict(
                    False,
                    f"host '{host}' is not on the network allowlist",
                    risk=risk,
                )

        # Rate limit (sliding window over allowed calls).
        rl = cap.constraints.rate_limit
        if rl is not None:
            now = time.monotonic()
            window = self._call_times[(agent_id, tool)]
            while window and now - window[0] > rl.window_seconds:
                window.popleft()
            if len(window) >= rl.max_calls:
                return Verdict(
                    False,
                    f"rate limit exceeded: {rl.max_calls} calls per "
                    f"{rl.window_seconds:g}s for {tool}",
                    risk=risk,
                )

        needs_approval = cap.requires_approval or tool_policy.requires_approval
        return Verdict(
            True,
            "allowed by policy",
            requires_approval=needs_approval,
            risk=risk,
        )

    def record_call(self, agent_id: str, tool: str) -> None:
        """Record an executed call for rate-limit accounting."""
        self._call_times[(agent_id, tool)].append(time.monotonic())
