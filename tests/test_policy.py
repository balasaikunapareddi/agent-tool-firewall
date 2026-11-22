"""Policy evaluator: the allow/deny matrix."""

from agent_tool_firewall.policy import Policy, PolicyEvaluator


def ev(policy: Policy, agent, tool, op, args=None):
    return PolicyEvaluator(policy).evaluate(agent, tool, op, args or {})


def test_unknown_agent_denied(policy):
    v = ev(policy, "ghost-agent", "docs", "search")
    assert v.blocked and "unknown agent" in v.reason


def test_granted_capability_allowed(policy):
    v = ev(policy, "research-agent", "docs", "search", {"query": "refund"})
    assert v.allowed


def test_ungranted_tool_denied(policy):
    v = ev(policy, "support-agent", "shell", "exec", {"command": "ls"})
    assert v.blocked and "no capability" in v.reason


def test_ungranted_operation_denied(policy):
    # support-agent may read files but not write them
    v = ev(policy, "support-agent", "file", "write", {"path": "docs/x.md"})
    assert v.blocked


def test_resource_in_scope_allowed(policy):
    v = ev(policy, "support-agent", "file", "read", {"path": "docs/refund-policy.md"})
    assert v.allowed


def test_resource_out_of_scope_denied(policy):
    v = ev(policy, "support-agent", "file", "read", {"path": "secrets/credentials.txt"})
    assert v.blocked and "outside allowed scope" in v.reason


def test_amount_within_cap_allowed(policy):
    v = ev(policy, "support-agent", "payments", "charge", {"amount": 50})
    assert v.allowed


def test_amount_over_cap_denied(policy):
    v = ev(policy, "support-agent", "payments", "charge", {"amount": 50.01})
    assert v.blocked and "exceeds cap" in v.reason


def test_admin_tool_requires_approval(policy):
    data = {
        "tools": {"admin": {"risk": "critical", "requires_approval": True}},
        "agents": {
            "ops-agent": {
                "capabilities": [{"tool": "admin", "operations": ["delete_user"]}]
            }
        },
    }
    v = ev(Policy.from_dict(data), "ops-agent", "admin", "delete_user", {"user_id": "u1"})
    assert v.allowed and v.requires_approval


def test_network_allowlist(policy):
    data = {
        "network": {"allowlist": ["api.internal.example.com"]},
        "agents": {
            "web-agent": {"capabilities": [{"tool": "http", "operations": ["post"]}]}
        },
    }
    p = Policy.from_dict(data)
    ok = ev(p, "web-agent", "http", "post", {"url": "https://api.internal.example.com/x"})
    assert ok.allowed
    bad = ev(p, "web-agent", "http", "post", {"url": "https://evil.example.com/x"})
    assert bad.blocked and "allowlist" in bad.reason


def test_rate_limit(policy):
    evaluator = PolicyEvaluator(policy)
    for _ in range(5):
        v = evaluator.evaluate(
            "support-agent", "payments", "charge", {"amount": 10}
        )
        assert v.allowed
        evaluator.record_call("support-agent", "payments")
    v = evaluator.evaluate("support-agent", "payments", "charge", {"amount": 10})
    assert v.blocked and "rate limit" in v.reason


def test_deny_by_default_for_unlisted_agent_tool_pairs(policy):
    # research-agent has no payments capability at all
    v = ev(policy, "research-agent", "payments", "charge", {"amount": 1})
    assert v.blocked
