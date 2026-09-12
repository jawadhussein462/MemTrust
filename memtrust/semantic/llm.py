"""Optional LLM-backed semantic analyzer.

Provider-agnostic: it wraps any ``complete(prompt) -> str`` callable, so it is
trivially mockable in tests and not coupled to any vendor. LLM calls:

* have a timeout,
* fail predictably (fall back to the heuristic analyzer, or treat the pair as
  a conflict, depending on ``fail_open``),
* never receive raw secrets — content is redacted before the prompt is built.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from ..exceptions import IntegrationError
from ..models.enums import MemoryRelationship
from ..models.memory import MemoryCandidate, MemoryRecord
from ..redaction import redact_text
from .base import SemanticAnalyzer
from .heuristic import HeuristicSemanticAnalyzer

Completer = Callable[[str], str]

_PROMPT = """You classify how a NEW memory relates to an EXISTING memory for an AI agent.
Respond with exactly one of these labels and nothing else:
duplicate, compatible, contradicts, supersedes, specializes, different_scope, unrelated.

Guidance: if the NEW memory is a newer version of the same fact (e.g. an updated
value), prefer "supersedes" over "contradicts".

EXISTING (created {existing_ts}): {existing}
NEW (created {candidate_ts}): {candidate}

Label:"""


class LLMSemanticAnalyzer:
    """Semantic analyzer backed by an arbitrary text-completion callable."""

    name = "llm"

    def __init__(
        self,
        complete: Completer,
        *,
        timeout: float = 10.0,
        fail_open: bool = True,
        fallback: SemanticAnalyzer | None = None,
    ) -> None:
        self._complete = complete
        self._timeout = timeout
        self._fail_open = fail_open
        self._fallback: SemanticAnalyzer = fallback or HeuristicSemanticAnalyzer()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="memtrust-llm")

    def compare(self, existing: MemoryRecord, candidate: MemoryCandidate) -> MemoryRelationship:
        existing_text, _ = redact_text(existing.content)
        candidate_text, _ = redact_text(candidate.content)
        prompt = _PROMPT.format(
            existing=existing_text,
            candidate=candidate_text,
            existing_ts=existing.created_at.isoformat(),
            candidate_ts=candidate.created_at.isoformat(),
        )
        try:
            raw = self._pool.submit(self._complete, prompt).result(timeout=self._timeout)
        except (FutureTimeout, Exception):  # noqa: B014 - explicit about timeout; behaviour configurable
            return self._on_failure(existing, candidate)

        rel = _parse_relationship(raw)
        if rel is None:
            return self._on_failure(existing, candidate)
        return rel

    def detect_generalization(self, candidate: MemoryCandidate) -> bool:
        detector = getattr(self._fallback, "detect_generalization", None)
        return bool(detector(candidate)) if detector else False

    def _on_failure(
        self, existing: MemoryRecord, candidate: MemoryCandidate
    ) -> MemoryRelationship:
        if self._fail_open:
            return self._fallback.compare(existing, candidate)
        # Fail closed: assume the worst (a conflict), which triggers review.
        return MemoryRelationship.CONTRADICTS


def _parse_relationship(raw: str) -> MemoryRelationship | None:
    text = raw.strip().lower()
    for rel in MemoryRelationship:
        if rel.value in text:
            return rel
    return None


def openai_completer(model: str = "gpt-4o-mini", *, client: object | None = None) -> Completer:
    """Build a ``complete`` callable backed by OpenAI (optional extra).

    Requires ``pip install "memtrust[openai]"``. The returned callable is what
    :class:`LLMSemanticAnalyzer` expects.
    """
    try:
        import openai  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise IntegrationError(
            "openai is not installed. Install with: pip install 'memtrust[openai]'"
        ) from exc

    from openai import OpenAI

    oai = client if client is not None else OpenAI()

    def complete(prompt: str) -> str:
        resp = oai.chat.completions.create(  # type: ignore[union-attr]
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=16,
        )
        return resp.choices[0].message.content or ""

    return complete


__all__ = ["Completer", "LLMSemanticAnalyzer", "openai_completer"]
