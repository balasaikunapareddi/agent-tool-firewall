"""Credential vault: secrets are injected at tool-call time, never shown
to agents, and redacted from anything that flows back.

The agent never holds a secret. When a tool needs credentials, the firewall
asks the vault for them and hands them directly to the tool. Everything the
tool returns passes through :meth:`Vault.redact` before the agent (or the
audit log) sees it, so a tool that echoes its credentials cannot leak them.
"""

from __future__ import annotations

import os
from typing import Any

REDACTED = "[REDACTED]"


class Vault:
    """In-memory secret store with injection and redaction.

    Secrets are loaded from environment variables (prefix ``VAULT_``) or
    passed in directly (tests/demo use clearly-marked fake fixtures).
    """

    def __init__(self, secrets: dict[str, str] | None = None):
        self._secrets: dict[str, str] = dict(secrets or {})

    @classmethod
    def from_env(cls, prefix: str = "VAULT_") -> "Vault":
        secrets = {
            key[len(prefix):].lower(): value
            for key, value in os.environ.items()
            if key.startswith(prefix) and value
        }
        return cls(secrets)

    def set(self, name: str, value: str) -> None:
        self._secrets[name] = value

    def names(self) -> list[str]:
        return sorted(self._secrets)

    def inject(self, required: list[str] | None) -> dict[str, str]:
        """Return the named secrets for a tool call. Missing names are omitted."""
        if not required:
            return {}
        return {name: self._secrets[name] for name in required if name in self._secrets}

    def redact(self, value: Any) -> Any:
        """Replace every known secret value in ``value`` with [REDACTED].

        Works recursively over strings, dicts, lists, and tuples. Empty
        secret values are ignored (they would match everywhere).
        """
        secrets = [s for s in self._secrets.values() if s]
        if not secrets:
            return value
        return self._redact(value, secrets)

    def _redact(self, value: Any, secrets: list[str]) -> Any:
        if isinstance(value, str):
            out = value
            for secret in secrets:
                if secret in out:
                    out = out.replace(secret, REDACTED)
            return out
        if isinstance(value, dict):
            return {k: self._redact(v, secrets) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(v, secrets) for v in value]
        return value

    def contains_secret(self, value: Any) -> bool:
        """True if any secret value appears anywhere in ``value``."""
        if isinstance(value, str):
            return any(s and s in value for s in self._secrets.values())
        if isinstance(value, dict):
            return any(self.contains_secret(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return any(self.contains_secret(v) for v in value)
        return False
