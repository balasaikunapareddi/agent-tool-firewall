"""Sandbox restrictions: path escapes, timeouts, output caps."""

import time

import pytest

from agent_tool_firewall.sandbox import Sandbox, SandboxViolation


def test_path_escape_rejected(sandbox):
    with pytest.raises(SandboxViolation):
        sandbox.context().resolve("../outside.txt")


def test_absolute_path_outside_root_rejected(sandbox):
    with pytest.raises(SandboxViolation):
        sandbox.context().resolve("/etc/passwd")


def test_path_inside_root_ok(sandbox):
    resolved = sandbox.context().resolve("docs/refund-policy.md")
    assert resolved.exists()


def test_timeout_cuts_off_slow_tool(tmp_path):
    sb = Sandbox(root=tmp_path, timeout_seconds=0.2)

    def slow(ctx, args):
        time.sleep(2)
        return "done"

    result = sb.execute(slow, {})
    assert not result.ok and result.timed_out


def test_output_is_capped(tmp_path):
    sb = Sandbox(root=tmp_path, max_output_chars=100)

    def chatty(ctx, args):
        return "x" * 5000

    result = sb.execute(chatty, {})
    assert result.ok
    assert len(result.output) < 200
    assert "truncated" in result.output


def test_tool_error_is_reported_not_raised(tmp_path):
    sb = Sandbox(root=tmp_path)

    def broken(ctx, args):
        raise ValueError("boom")

    result = sb.execute(broken, {})
    assert not result.ok
    assert "boom" in result.error


def test_sandbox_violation_inside_tool_is_caught(tmp_path):
    sb = Sandbox(root=tmp_path)

    def sneaky(ctx, args):
        return ctx.read_text("../../etc/passwd")

    result = sb.execute(sneaky, {})
    assert not result.ok
    assert "sandbox violation" in result.error
