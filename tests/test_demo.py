"""End-to-end demo: 5/5 attacks succeed without the firewall, 5/5 blocked
with it, and legitimate work completes in both worlds."""

from agent_tool_firewall.demo import run_demo
from agent_tool_firewall.tools import FAKE_DB_PASSWORD, FAKE_PAYMENTS_KEY


def test_demo_end_to_end(tmp_path):
    result = run_demo(workdir=tmp_path)

    # Without the firewall every attack lands.
    assert result.attacks_succeeded_without == 5
    assert result.world_without.users.get("user-1001") is None  # deleted
    assert len(result.world_without.http_requests) == 1  # exfiltrated
    assert any(c["amount"] == 9999 for c in result.world_without.charges)
    assert result.world_without.shell_commands == ["cat /etc/passwd"]

    # With the firewall every attack is blocked...
    assert result.attacks_blocked_with == 5
    assert "user-1001" in result.world_with.users  # still exists
    assert result.world_with.http_requests == []
    assert result.world_with.shell_commands == []
    assert all(c["amount"] <= 50 for c in result.world_with.charges)

    # ...and legitimate work still completes.
    research = result.with_firewall["research-agent"]
    assert research.succeeded == len(research.steps) == 3
    support = result.with_firewall["support-agent"]
    legit = [s for s in support.steps if "within cap" in s.label]
    assert legit and legit[0].ok


def test_demo_audit_is_complete_and_secret_free(tmp_path):
    result = run_demo(workdir=tmp_path)
    # 3 research + 7 support attempts, all recorded.
    assert len(result.audit.entries) == 10
    assert len(result.audit.blocked()) == 5
    log_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    # Secret VALUES must never appear (args are hashed; reasons/details are
    # redacted). Paths in denial reasons are fine — they explain the block.
    assert FAKE_PAYMENTS_KEY not in log_text
    assert FAKE_DB_PASSWORD not in log_text
