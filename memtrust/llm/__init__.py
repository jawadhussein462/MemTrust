"""Provider-agnostic LLM layer used by the semantic checks.

MemTrust never requires an LLM: the default pipeline is deterministic and
offline. The checks in :mod:`memtrust.checks.semantic` take any object
implementing :class:`LLMClient`; :class:`memtrust.llm.openai.OpenAIClient`
is the bundled implementation (``pip install "memtrust[openai]"``).

Memory content is untrusted input to the judge model itself, so every
prompt wraps it with :func:`spotlight` (randomized delimiters, Hines et al.
2024, "Defending Against Indirect Prompt Injection Attacks With
Spotlighting") and asks for schema-constrained output, which leaves an
injected instruction no free-text channel to steer.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable

from ..exceptions import MemTrustError


class LLMError(MemTrustError):
    """An LLM call failed, timed out, refused, or returned malformed output."""


@runtime_checkable
class LLMClient(Protocol):
    """Minimal interface the semantic checks need from a model provider."""

    model: str

    def complete(self, *, system: str, user: str, max_tokens: int = 256) -> str:
        """Free-text completion."""
        ...

    def complete_json(
        self, *, system: str, user: str, schema: dict[str, Any], name: str
    ) -> dict[str, Any]:
        """Completion constrained to ``schema`` (JSON Schema, strict mode)."""
        ...


def spotlight(text: str) -> tuple[str, str]:
    """Wrap untrusted ``text`` in a random, unforgeable delimiter.

    Returns ``(wrapped, tag)``. The tag is random per call, so content cannot
    close the block early by guessing it; any occurrence is removed anyway.
    """
    tag = f"untrusted-{secrets.token_hex(6)}"
    safe = text.replace(tag, "")
    return f"<{tag}>\n{safe}\n</{tag}>", tag


class ResultCache:
    """Small thread-safe LRU for LLM verdicts, keyed by a hash of the inputs.

    Reads repeat: the same record is retrieved many times, so caching by
    content keeps read-time semantic checks affordable.
    """

    def __init__(self, maxsize: int = 2048) -> None:
        self._maxsize = maxsize
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def key(*parts: str) -> str:
        digest = hashlib.sha256()
        for part in parts:
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()

    def get(self, key: str) -> Any | None:
        with self._lock:
            if key not in self._data:
                return None
            self._data.move_to_end(key)
            return self._data[key]

    def put(self, key: str, value: Any) -> None:
        if self._maxsize <= 0:
            return
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


__all__ = ["LLMClient", "LLMError", "ResultCache", "spotlight"]
