"""FilterRAG: frequency-density filtering of retrieved texts.

From *Defending Against Knowledge Poisoning Attacks During
Retrieval-Augmented Generation* (arXiv:2508.02835). PoisonedRAG-style
passages must rank highly for a target query *and* steer the answer, so they
are stuffed with query- and answer-related words. FilterRAG scores each
retrieved text with

    Freq-Density(d) = sum_{w in (q ⊕ a) ∩ d} Freq(w, d) / UniqueWords(d)

where ``q`` is the query, ``a`` an answer a small language model produces
from ``(q, d)``, and ``∩`` matches words exactly or by embedding similarity
above a threshold (paper default 0.6 with ``all-MiniLM-L6-v2``). Texts with
density at or above ``epsilon`` (paper default 0.2) are dropped.

This implementation:

* takes the query from ``context.query`` (``MemorySec.scan(records, query=...)``)
  or ``candidate.metadata["query"]``,
  and does nothing when neither is available;
* optionally calls ``answer(query, text)`` -- any callable, e.g. a small
  local model -- to build ``q ⊕ a`` as in the paper (query-only overlap is
  a weaker signal, as the authors note);
* matches content words exactly, or via ``word_similarity`` when given;
  stopwords never count toward the numerator;
* skips texts with fewer than ``min_unique_words`` (default 20): the
  metric was designed for passage-length retrieval units, and on a one-line
  fact two or three overlapping words already exceed ``epsilon``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from ....context import CheckContext
from ....exceptions import ConfigurationError
from ....models.memory import MemoryCandidate
from ....text import _STOPWORDS, tokenize
from ..base import BaseDetector, Detection

Answer = Callable[[str, str], str]
WordSimilarity = Callable[[str, str], float]


def freq_density(
    text: str,
    query_answer: str,
    *,
    word_similarity: WordSimilarity | None = None,
    similarity_threshold: float = 0.6,
) -> tuple[float, int, int]:
    """Return ``(density, matched_word_count, unique_word_count)`` for ``text``."""
    doc_tokens = tokenize(text)
    counts = Counter(doc_tokens)
    unique = len(counts)
    if unique == 0:
        return 0.0, 0, 0
    qa_words = {w for w in tokenize(query_answer) if w not in _STOPWORDS}
    if not qa_words:
        return 0.0, 0, unique
    matched: set[str] = set()
    for word in counts:
        if word in _STOPWORDS:
            continue
        exact = word in qa_words
        semantic = word_similarity is not None and any(
            word_similarity(word, q) >= similarity_threshold for q in qa_words
        )
        if exact or semantic:
            matched.add(word)
    total = sum(counts[w] for w in matched)
    return total / unique, len(matched), unique


class FilterRAGDetector(BaseDetector):
    """Flag retrieved texts whose query/answer word density looks optimised."""

    name = "filterrag"

    def __init__(
        self,
        *,
        epsilon: float = 0.2,
        answer: Answer | None = None,
        word_similarity: WordSimilarity | None = None,
        similarity_threshold: float = 0.6,
        min_unique_words: int = 20,
        query_key: str = "query",
    ) -> None:
        if epsilon <= 0:
            raise ConfigurationError("epsilon must be positive.")
        if not 0.0 < similarity_threshold <= 1.0:
            raise ConfigurationError("similarity_threshold must be within (0, 1].")
        self.epsilon = epsilon
        self.answer = answer
        self.word_similarity = word_similarity
        self.similarity_threshold = similarity_threshold
        self.min_unique_words = max(1, min_unique_words)
        self.query_key = query_key

    def query_for(self, candidate: MemoryCandidate, context: CheckContext) -> str | None:
        if context.query:
            return context.query
        value = candidate.metadata.get(self.query_key)
        return value if isinstance(value, str) and value.strip() else None

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]:
        query = self.query_for(candidate, context)
        if query is None:
            return []
        query_answer = query
        if self.answer is not None:
            query_answer = f"{query} {self.answer(query, candidate.content)}"
        density, matched, unique = freq_density(
            candidate.content,
            query_answer,
            word_similarity=self.word_similarity,
            similarity_threshold=self.similarity_threshold,
        )
        if unique < self.min_unique_words or density < self.epsilon:
            return []
        return [
            self.hit(
                code="memory_poisoning",
                score=min(density, 1.0),
                freq_density=round(density, 3),
                matched_words=matched,
                unique_words=unique,
                epsilon=self.epsilon,
            )
        ]


__all__ = ["FilterRAGDetector", "freq_density"]
