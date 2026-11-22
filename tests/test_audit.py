"""Audit log: completeness, hashing, append-only persistence."""

import json

from agent_tool_firewall.audit import AuditLog, hash_args


def test_args_are_hashed_not_stored(audit):
    entry = audit.record(
        agent="a",
        tool="payments",
        operation="charge",
        args={"amount": 10, "note": "secret-ish"},
        verdict="allowed",
        reason="ok",
        outcome="success",
    )
    assert entry.args_hash == hash_args({"amount": 10, "note": "secret-ish"})
    assert "secret-ish" not in entry.args_hash


def test_hash_is_deterministic_and_order_insensitive():
    assert hash_args({"a": 1, "b": 2}) == hash_args({"b": 2, "a": 1})


def test_entries_persist_as_jsonl(audit, tmp_path):
    audit.record(
        agent="a", tool="docs", operation="search", args={},
        verdict="allowed", reason="ok", outcome="success",
    )
    audit.record(
        agent="a", tool="shell", operation="exec", args={"command": "ls"},
        verdict="blocked", reason="no capability", outcome="blocked",
    )
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[1]["verdict"] == "blocked"
    assert "command" not in json.dumps(parsed[1])  # raw args never stored


def test_summary_counts(audit):
    for outcome in ("success", "success", "blocked", "error"):
        audit.record(
            agent="a", tool="t", operation="o", args={},
            verdict="allowed", reason="", outcome=outcome,
        )
    assert audit.summary() == {"success": 2, "blocked": 1, "error": 1}


def test_for_agent_filter(audit):
    audit.record(agent="x", tool="t", operation="o", args={}, verdict="allowed", reason="", outcome="success")
    audit.record(agent="y", tool="t", operation="o", args={}, verdict="allowed", reason="", outcome="success")
    assert len(audit.for_agent("x")) == 1
