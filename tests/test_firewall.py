"""Firewall behavior: enforcement, approval gates, redaction, audit."""

from agent_tool_firewall.firewall import ToolFirewall
from agent_tool_firewall.policy import Policy
from agent_tool_firewall.tools import FAKE_PAYMENTS_KEY, build_mock_registry


def test_allowed_call_executes(firewall, world):
    result = firewall.call("support-agent", "payments", "charge", {"amount": 25, "customer": "user-1002"})
    assert result.ok
    assert world.charges == [{"amount": 25.0, "customer": "user-1002"}]


def test_blocked_call_does_not_execute(firewall, world):
    result = firewall.call("support-agent", "payments", "charge", {"amount": 9999})
    assert result.blocked and not result.ok
    assert world.charges == []


def test_secret_redacted_from_tool_output(firewall):
    # The mock payments tool echoes its injected API key in the receipt.
    result = firewall.call("support-agent", "payments", "charge", {"amount": 10})
    assert result.ok
    assert FAKE_PAYMENTS_KEY not in str(result.output)
    assert "[REDACTED]" in result.output["receipt"]


def test_agent_never_receives_credentials(firewall, vault):
    result = firewall.call("research-agent", "docs", "search", {"query": "refund"})
    assert result.ok
    assert not vault.contains_secret(result.output)


def test_blocked_attempt_is_audited(firewall, audit):
    firewall.call("support-agent", "shell", "exec", {"command": "cat /etc/passwd"})
    blocked = audit.blocked()
    assert len(blocked) == 1
    assert blocked[0].tool == "shell"
    assert blocked[0].verdict == "blocked"


def test_every_attempt_is_audited(firewall, audit):
    firewall.call("research-agent", "docs", "search", {"query": "x"})
    firewall.call("support-agent", "shell", "exec", {"command": "ls"})
    firewall.call("support-agent", "payments", "charge", {"amount": 9999})
    assert len(audit.entries) == 3
    assert audit.summary() == {"success": 1, "blocked": 2}


def test_audit_log_never_contains_secrets(firewall, audit, tmp_path):
    firewall.call("support-agent", "payments", "charge", {"amount": 10})
    log_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert FAKE_PAYMENTS_KEY not in log_text
    for entry in audit.entries:
        assert FAKE_PAYMENTS_KEY not in entry.reason
        assert FAKE_PAYMENTS_KEY not in entry.detail


def test_approval_required_without_approver(policy, world, vault, sandbox, audit):
    data = {
        "tools": {"admin": {"risk": "critical", "requires_approval": True}},
        "agents": {
            "ops-agent": {"capabilities": [{"tool": "admin", "operations": ["delete_user"]}]}
        },
    }
    fw = ToolFirewall(Policy.from_dict(data), build_mock_registry(world), vault, audit, sandbox)
    result = fw.call("ops-agent", "admin", "delete_user", {"user_id": "user-1001"})
    assert result.blocked
    assert result.verdict == "approval_required"
    assert "user-1001" in world.users  # nothing happened


def test_approval_denied_by_human(policy, world, vault, sandbox, audit):
    data = {
        "tools": {"admin": {"risk": "critical", "requires_approval": True}},
        "agents": {
            "ops-agent": {"capabilities": [{"tool": "admin", "operations": ["delete_user"]}]}
        },
    }
    fw = ToolFirewall(
        Policy.from_dict(data),
        build_mock_registry(world),
        vault,
        audit,
        sandbox,
        approver=lambda *a: False,
    )
    result = fw.call("ops-agent", "admin", "delete_user", {"user_id": "user-1001"})
    assert result.blocked and result.verdict == "approval_denied"
    assert "user-1001" in world.users


def test_approval_granted_by_human(policy, world, vault, sandbox, audit):
    data = {
        "tools": {"admin": {"risk": "critical", "requires_approval": True}},
        "agents": {
            "ops-agent": {"capabilities": [{"tool": "admin", "operations": ["delete_user"]}]}
        },
    }
    fw = ToolFirewall(
        Policy.from_dict(data),
        build_mock_registry(world),
        vault,
        audit,
        sandbox,
        approver=lambda *a: True,
    )
    result = fw.call("ops-agent", "admin", "delete_user", {"user_id": "user-1001"})
    assert result.ok
    assert "user-1001" not in world.users


def test_unknown_tool_blocked(firewall):
    result = firewall.call("research-agent", "teleport", "beam", {})
    assert result.blocked


def test_direct_runner_has_no_protection(direct, world):
    # Baseline for the demo comparison: without the firewall, the
    # credentials file is readable and the secret reaches the caller.
    result = direct.call("support-agent", "file", "read", {"path": "secrets/credentials.txt"})
    assert result.ok
    assert FAKE_PAYMENTS_KEY in result.output["content"]
