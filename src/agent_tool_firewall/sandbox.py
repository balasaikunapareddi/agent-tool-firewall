"""Sandboxed execution wrapper.

Tools never run with the agent's (or the host process's) full reach. The
sandbox gives each call:

- a **restricted filesystem view**: file paths resolve inside a sandbox
  root; ``..`` escapes and absolute paths outside the root are rejected;
- a **hard timeout**: a tool that hangs is cut off;
- an **output cap**: oversized tool output is truncated before the agent
  sees it, so a tool cannot flood the agent's context.

In this reference implementation the "tools" are safe mocks, but the wrapper
is written the way you would wrap real ones: the handler receives a
:class:`SandboxContext` and can only touch the world through it.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class SandboxViolation(Exception):
    """Raised when a tool tries to escape its sandbox."""


@dataclass
class SandboxContext:
    root: Path
    credentials: dict[str, str] = field(default_factory=dict)

    def resolve(self, path: str) -> Path:
        """Resolve ``path`` inside the sandbox root or raise SandboxViolation."""
        candidate = (self.root / path).resolve()
        root = self.root.resolve()
        if candidate != root and root not in candidate.parents:
            raise SandboxViolation(f"path '{path}' escapes the sandbox root")
        return candidate

    def read_text(self, path: str) -> str:
        return self.resolve(path).read_text(encoding="utf-8")

    def write_text(self, path: str, content: str) -> None:
        target = self.resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


@dataclass
class ExecutionResult:
    ok: bool
    output: Any = None
    error: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False


class Sandbox:
    def __init__(
        self,
        root: str | Path,
        timeout_seconds: float = 5.0,
        max_output_chars: int = 4000,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def context(self, credentials: dict[str, str] | None = None) -> SandboxContext:
        return SandboxContext(root=self.root, credentials=dict(credentials or {}))

    def execute(
        self,
        handler: Callable[[SandboxContext, dict[str, Any]], Any],
        args: dict[str, Any],
        credentials: dict[str, str] | None = None,
    ) -> ExecutionResult:
        ctx = self.context(credentials)
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, ctx, args)
            try:
                output = future.result(timeout=self.timeout_seconds)
            except concurrent.futures.TimeoutError:
                return ExecutionResult(
                    ok=False,
                    error=f"tool timed out after {self.timeout_seconds:g}s",
                    duration_ms=(time.monotonic() - start) * 1000,
                    timed_out=True,
                )
            except SandboxViolation as exc:
                return ExecutionResult(
                    ok=False,
                    error=f"sandbox violation: {exc}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )
            except Exception as exc:  # tool errors are data, not crashes
                return ExecutionResult(
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=(time.monotonic() - start) * 1000,
                )
        return ExecutionResult(
            ok=True,
            output=self._cap(output),
            duration_ms=(time.monotonic() - start) * 1000,
        )

    def _cap(self, output: Any) -> Any:
        if isinstance(output, str) and len(output) > self.max_output_chars:
            return output[: self.max_output_chars] + "\n…[output truncated by sandbox]"
        if isinstance(output, dict):
            return {k: self._cap(v) for k, v in output.items()}
        if isinstance(output, list):
            return [self._cap(v) for v in output]
        return output
