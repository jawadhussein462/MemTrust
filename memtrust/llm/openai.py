"""OpenAI implementation of :class:`memtrust.llm.LLMClient`.

Install with ``pip install "memtrust[openai]"``. Configure through the
environment (see ``.env.example``)::

    OPENAI_API_KEY=sk-...
    MEMTRUST_OPENAI_MODEL=gpt-5-mini          # optional
    MEMTRUST_OPENAI_REASONING_EFFORT=low      # optional, reasoning models only
    OPENAI_BASE_URL=https://...               # optional (Azure/OpenAI-compatible gateways)
    MEMTRUST_LLM_TIMEOUT=15                   # optional, seconds

Structured output uses ``response_format={"type": "json_schema", "strict":
true}``, so verdicts always parse against the schema.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..exceptions import IntegrationError
from . import LLMError
from .env import load_dotenv

DEFAULT_MODEL = "gpt-5-mini"
_REASONING_PREFIXES = ("gpt-5", "o1", "o3", "o4")


class OpenAIClient:
    """Chat Completions client with strict JSON-schema output.

    Pass ``client`` to reuse a configured ``openai.OpenAI`` (or a test
    double); otherwise one is created from ``api_key`` / ``base_url``.
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 15.0,
        max_retries: int = 2,
        reasoning_effort: str | None = None,
        client: Any = None,
    ) -> None:
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        if reasoning_effort is None and self.model.startswith(_REASONING_PREFIXES):
            reasoning_effort = "low"  # verdicts are short; keep latency down
        self.reasoning_effort = reasoning_effort
        if client is None:
            try:
                import openai
            except ImportError as exc:
                raise IntegrationError(
                    'OpenAIClient needs the openai package: pip install "memtrust[openai]"'
                ) from exc
            client = openai.OpenAI(
                api_key=api_key, base_url=base_url, timeout=timeout, max_retries=max_retries
            )
        self._client = client

    @classmethod
    def from_env(cls, *, dotenv: str | None = ".env", **overrides: Any) -> OpenAIClient:
        """Build a client from environment variables (and ``.env`` if present)."""
        if dotenv:
            load_dotenv(dotenv)
        api_key = overrides.pop("api_key", None) or os.environ.get("OPENAI_API_KEY")
        if not api_key and "client" not in overrides:
            raise IntegrationError(
                "OPENAI_API_KEY is not set. Copy .env.example to .env and add your key."
            )
        timeout = float(os.environ.get("MEMTRUST_LLM_TIMEOUT", "15"))
        return cls(
            model=overrides.pop("model", None) or os.environ.get("MEMTRUST_OPENAI_MODEL"),
            api_key=api_key,
            base_url=overrides.pop("base_url", None) or os.environ.get("OPENAI_BASE_URL"),
            timeout=overrides.pop("timeout", timeout),
            reasoning_effort=overrides.pop("reasoning_effort", None)
            or os.environ.get("MEMTRUST_OPENAI_REASONING_EFFORT"),
            **overrides,
        )

    def complete(self, *, system: str, user: str, max_tokens: int = 256) -> str:
        message = self._create(system, user, max_tokens=max_tokens)
        return str(message.content or "")

    def complete_json(
        self, *, system: str, user: str, schema: dict[str, Any], name: str
    ) -> dict[str, Any]:
        response_format = {
            "type": "json_schema",
            "json_schema": {"name": name, "schema": schema, "strict": True},
        }
        message = self._create(system, user, max_tokens=2048, response_format=response_format)
        if getattr(message, "refusal", None):
            raise LLMError(f"model refused: {message.refusal}")
        try:
            parsed = json.loads(message.content or "")
        except json.JSONDecodeError as exc:
            raise LLMError("model returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise LLMError("model returned a non-object JSON value")
        return parsed

    def _create(self, system: str, user: str, *, max_tokens: int, **extra: Any) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_completion_tokens": max_tokens
            if not self.reasoning_effort
            else max(max_tokens, 2048),
            "timeout": self.timeout,
            **extra,
        }
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        try:
            response = self._client.chat.completions.create(**kwargs)
            return response.choices[0].message
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(f"OpenAI request failed: {type(exc).__name__}: {exc}") from exc


__all__ = ["DEFAULT_MODEL", "OpenAIClient"]
