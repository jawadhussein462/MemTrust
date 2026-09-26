"""Local prompt-injection classifier (no API calls).

Wraps a Hugging Face text-classification model. Defaults to Meta's Llama
Prompt Guard 2 (86M, mDeBERTa-base; gated on Hugging Face, accept the
license first). ``leolee99/PIGuard`` (InjecGuard/PIGuard, trained to reduce
over-defense on trigger words, evaluated on NotInject) is an ungated
alternative. Both read ~512 tokens, so long text is scanned in overlapping
windows.

Install ``pip install "memtrust[classifier]"`` (plus a torch build for your
platform). Cheap enough to run on reads.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from ...context import CheckContext
from ...exceptions import IntegrationError
from ...llm import ResultCache
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ._base import ModelCheck, OnError

DEFAULT_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"
MALICIOUS_LABELS = frozenset({"label_1", "malicious", "injection", "jailbreak", "unsafe"})

Classifier = Callable[[list[str]], Sequence[dict[str, Any]]]


class PromptGuardCheck(ModelCheck):
    """Flag injection/jailbreak text with a local classifier."""

    name = "prompt_guard"

    def __init__(
        self,
        classifier: Classifier | None = None,
        *,
        model: str = DEFAULT_MODEL,
        threshold: float = 0.5,
        malicious_labels: frozenset[str] = MALICIOUS_LABELS,
        on_error: OnError = "open",
        on_read: bool = True,
        window_chars: int = 1500,
        max_windows: int = 16,
    ) -> None:
        super().__init__(
            on_error=on_error, on_read=on_read, max_chars=window_chars, max_chunks=max_windows
        )
        self.model = model
        self.threshold = threshold
        self.malicious_labels = frozenset(label.lower() for label in malicious_labels)
        self._classifier = classifier

    def _classify(self, texts: list[str]) -> Sequence[dict[str, Any]]:
        if self._classifier is None:
            try:
                from transformers import pipeline
            except ImportError as exc:
                raise IntegrationError(
                    'PromptGuardCheck needs transformers: pip install "memtrust[classifier]"'
                ) from exc
            self._classifier = pipeline("text-classification", model=self.model, truncation=True)
        return self._classifier(texts)

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        windows, truncated = self._chunks(candidate.content)
        key = ResultCache.key("prompt-guard-v1", self.model, candidate.content)
        try:
            score = self._cached(key, lambda: self._max_malicious(windows))
        except Exception as exc:  # model load or inference failure
            return self._failure(exc)
        findings: list[Finding] = []
        if score >= self.threshold:
            findings.append(
                Finding(
                    code="persistent_instruction",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    message="Classifier: content looks like a prompt injection or jailbreak.",
                    evidence={"detector": "prompt_guard", "model": self.model, "score": score},
                    check=self.name,
                    recommended_action=Action.REVIEW,
                )
            )
        if truncated:
            findings.append(self._truncated())
        return findings

    def _max_malicious(self, windows: list[str]) -> float:
        best = 0.0
        for result in self._classify(windows):
            label = str(result.get("label", "")).lower()
            if label in self.malicious_labels:
                best = max(best, float(result.get("score", 0.0)))
        return round(best, 4)


__all__ = ["DEFAULT_MODEL", "PromptGuardCheck"]
