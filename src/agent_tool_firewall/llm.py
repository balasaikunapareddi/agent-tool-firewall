"""Model access: deterministic mock by default, real model via LiteLLM.

Mock mode needs no key and no network — agents follow fixed scripts, so the
demo and the tests are reproducible. Live mode uses LiteLLM so any provider
works by changing ``LLM_MODEL`` (default ``gemini/gemini-3.5-flash-lite``);
the provider key comes from that provider's standard environment variable
(``GEMINI_API_KEY``, ``GROQ_API_KEY``, ``OPENROUTER_API_KEY``, ...). Ollama
needs no key. Transient 429/503s are retried with backoff.
"""

from __future__ import annotations

import os
import time
from typing import Any

DEFAULT_MODEL = "gemini/gemini-3.5-flash-lite"


def live_model() -> str:
    return os.environ.get("LLM_MODEL", DEFAULT_MODEL)


def completion_with_retry(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                          model: str | None = None, max_attempts: int = 4) -> Any:
    """litellm.completion with exponential backoff on 429/503."""
    import litellm  # lazy: mock mode must work without litellm installed

    model = model or live_model()
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            kwargs: dict[str, Any] = {"model": model, "messages": messages}
            if tools:
                kwargs["tools"] = tools
            return litellm.completion(**kwargs)
        except Exception as exc:  # provider errors vary; match on status text
            text = f"{type(exc).__name__}: {exc}"
            if not any(code in text for code in ("429", "503", "RateLimit", "ServiceUnavailable")):
                raise
            last_exc = exc
            time.sleep(min(30, 2 ** attempt * 2))
    raise RuntimeError(f"LLM unavailable after {max_attempts} attempts: {last_exc}")
