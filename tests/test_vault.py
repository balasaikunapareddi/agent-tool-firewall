"""Vault: injection scope and redaction."""

from agent_tool_firewall.tools import FAKE_DB_PASSWORD, FAKE_PAYMENTS_KEY
from agent_tool_firewall.vault import REDACTED, Vault


def test_inject_only_requested_secrets(vault):
    injected = vault.inject(["payments_api_key"])
    assert injected == {"payments_api_key": FAKE_PAYMENTS_KEY}
    assert "db_password" not in injected


def test_inject_missing_secret_is_omitted(vault):
    assert vault.inject(["nonexistent"]) == {}


def test_redact_string(vault):
    out = vault.redact(f"key is {FAKE_PAYMENTS_KEY} ok")
    assert FAKE_PAYMENTS_KEY not in out
    assert REDACTED in out


def test_redact_nested_structures(vault):
    payload = {
        "receipt": f"charged via {FAKE_PAYMENTS_KEY}",
        "items": [FAKE_DB_PASSWORD, {"nested": FAKE_PAYMENTS_KEY}],
        "amount": 25,
    }
    out = vault.redact(payload)
    assert not vault.contains_secret(out)
    assert out["amount"] == 25


def test_contains_secret(vault):
    assert vault.contains_secret(f"leak: {FAKE_DB_PASSWORD}")
    assert not vault.contains_secret("nothing sensitive here")


def test_empty_secret_values_ignored():
    v = Vault({"blank": ""})
    assert v.redact("hello") == "hello"


def test_from_env(monkeypatch):
    monkeypatch.setenv("VAULT_API_TOKEN", "tok-123")
    monkeypatch.setenv("OTHER", "nope")
    v = Vault.from_env()
    assert v.inject(["api_token"]) == {"api_token": "tok-123"}
    assert v.names() == ["api_token"]
