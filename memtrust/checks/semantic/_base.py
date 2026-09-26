"""Shared plumbing for model-backed checks: caching, chunking, failure policy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeVar

from ...llm import LLMError, ResultCache
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ..base import WRITE, WRITE_AND_READ, BaseCheck

OnError = Literal["open", "closed"]
T = TypeVar("T")


class ModelCheck(BaseCheck):
    """Base for checks that call a model.

    * ``on_error="open"`` (default): a failed call yields an INFO
      ``model_unavailable`` finding and the deterministic checks still decide.
      ``"closed"`` raises, so the engine's ``fail_closed`` blocks the write.
    * Verdicts are cached by content hash, so repeated reads cost nothing.
    * ``on_read=True`` also runs the check on retrieved records.
    """

    name = "model"

    def __init__(
        self,
        *,
        on_error: OnError = "open",
        on_read: bool = False,
        cache_size: int = 2048,
        max_chars: int = 6000,
        max_chunks: int = 4,
    ) -> None:
        if on_error not in ("open", "closed"):
            raise ValueError("on_error must be 'open' or 'closed'")
        self.on_error = on_error
        self.operations = WRITE_AND_READ if on_read else WRITE
        self.cache = ResultCache(cache_size)
        self.max_chars = max_chars
        self.max_chunks = max_chunks

    def _cached(self, key: str, compute: Callable[[], T]) -> T:
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        value = compute()
        self.cache.put(key, value)
        return value

    def _chunks(self, text: str) -> tuple[list[str], bool]:
        """Split long text into overlapping windows; report if it was cut short."""
        if len(text) <= self.max_chars:
            return [text], False
        step = self.max_chars - min(500, self.max_chars // 5)
        chunks: list[str] = []
        start = 0
        while True:
            chunks.append(text[start : start + self.max_chars])
            if start + self.max_chars >= len(text):
                return chunks, False
            if len(chunks) == self.max_chunks:
                return chunks, True
            start += step

    def _failure(self, exc: Exception) -> list[Finding]:
        if self.on_error == "closed":
            raise exc
        return [
            Finding(
                code="model_unavailable",
                category=Category.SECURITY,
                severity=Severity.INFO,
                message=(
                    f"Check '{self.name}' could not reach its model; deterministic checks apply."
                ),
                evidence={"error_type": type(exc).__name__},
                check=self.name,
                recommended_action=Action.ALLOW,
            )
        ]

    def _truncated(self) -> Finding:
        return Finding(
            code="model_input_truncated",
            category=Category.SECURITY,
            severity=Severity.LOW,
            message=f"Content exceeds what '{self.name}' inspects; only the start was checked.",
            evidence={"max_chars": self.max_chars * self.max_chunks},
            check=self.name,
            recommended_action=Action.ALLOW_WITH_WARNING,
        )


__all__ = ["LLMError", "ModelCheck", "OnError"]
