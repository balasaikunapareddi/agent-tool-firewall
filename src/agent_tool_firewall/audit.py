"""Append-only audit log.

Every attempted tool call is recorded — allowed, blocked, or held for
approval — with the policy verdict and the outcome. Arguments are stored as
a SHA-256 hash of their canonical JSON form, never in raw form, so secrets
that appear in arguments cannot leak through the log. The log is append-only
JSONL on disk plus an in-memory copy for inspection.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable


def hash_args(args: dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    timestamp: float
    agent: str
    tool: str
    operation: str
    args_hash: str
    verdict: str  # allowed | blocked | approval_required | approval_denied
    reason: str
    outcome: str  # success | error | blocked | timeout
    risk: str = "medium"
    duration_ms: float | None = None
    detail: str = ""


@dataclass
class AuditLog:
    path: str | Path | None = None
    # Optional redactor (e.g. Vault.redact) applied to reason/detail text so a
    # secret value can never reach the log even via an error message.
    redactor: Callable[[Any], Any] | None = None
    entries: list[AuditEntry] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(
        self,
        *,
        agent: str,
        tool: str,
        operation: str,
        args: dict[str, Any],
        verdict: str,
        reason: str,
        outcome: str,
        risk: str = "medium",
        duration_ms: float | None = None,
        detail: str = "",
    ) -> AuditEntry:
        if self.redactor is not None:
            reason = self.redactor(reason)
            detail = self.redactor(detail)
        entry = AuditEntry(
            timestamp=time.time(),
            agent=agent,
            tool=tool,
            operation=operation,
            args_hash=hash_args(args),
            verdict=verdict,
            reason=reason,
            outcome=outcome,
            risk=risk,
            duration_ms=duration_ms,
            detail=detail,
        )
        with self._lock:
            self.entries.append(entry)
            if self.path is not None:
                path = Path(self.path)
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def blocked(self) -> list[AuditEntry]:
        return [e for e in self.entries if e.outcome == "blocked"]

    def for_agent(self, agent: str) -> list[AuditEntry]:
        return [e for e in self.entries if e.agent == agent]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e.outcome] = counts.get(e.outcome, 0) + 1
        return counts
