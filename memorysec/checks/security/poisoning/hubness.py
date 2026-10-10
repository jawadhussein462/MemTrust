"""Hubness / k-occurrence: poison that wants to be retrieved becomes a hub.

Radovanović, Nanopoulos, and Ivanović, "Hubs in Space", JMLR 2010. A hub
is a point that appears in many other points' k-nearest-neighbour lists.
Mean k-occurrence in a corpus is `k`. Applying this to RAG poisoning is
the hypothesis: a passage written to match many queries sits close to
many stored memories and becomes an outlier hub.

Needs stored embeddings on the scanned batch. Without them this detector
returns nothing. The k-occurrence table is computed once per scan and
cached on `context.cache`.
"""

from __future__ import annotations

from ....context import CheckContext
from ....exceptions import ConfigurationError
from ....models.memory import MemoryCandidate
from ....vectors import k_occurrence, with_embeddings
from ..base import BaseDetector, Detection

_CACHE_KEY = "hubness.k_occurrence"


class HubnessDetector(BaseDetector):
    """Flag a memory that appears in unusually many other records' k-NN lists.

    The finding code is `hub_record`. Records without embeddings, and
    batches smaller than `min_corpus`, are skipped.
    """

    name = "hubness"

    def __init__(
        self,
        *,
        k: int = 10,
        factor: float = 3.0,
        min_occurrence: int | None = None,
        min_corpus: int = 8,
    ) -> None:
        """Store the neighbourhood size and the hub cutoff.

        Args:
            k: Neighbourhood size. Default `10`. Must be at least 1.
            factor: Flag a record whose k-occurrence is at least
                `factor * k`. Default `3.0`. Mean occurrence is `k`, so
                `3` means three times the average.
            min_occurrence: Absolute cutoff used instead of `factor * k`
                when set. Useful in tests with a tiny corpus.
            min_corpus: Skip batches with fewer embedded records than this.
                Default `8`.

        Raises:
            ConfigurationError: `k` or `min_corpus` is below 1, or
                `factor` is not positive.
        """
        if k < 1:
            raise ConfigurationError("k must be >= 1.")
        if factor <= 0:
            raise ConfigurationError("factor must be > 0.")
        if min_corpus < 1:
            raise ConfigurationError("min_corpus must be >= 1.")
        if min_occurrence is not None and min_occurrence < 1:
            raise ConfigurationError("min_occurrence must be >= 1.")
        self.k = k
        self.factor = factor
        self.min_occurrence = min_occurrence
        self.min_corpus = min_corpus

    def _counts(self, context: CheckContext) -> dict[str, int]:
        cached = context.cache.get(_CACHE_KEY)
        if isinstance(cached, dict):
            return cached
        counts = k_occurrence(context.existing, k=self.k)
        context.cache[_CACHE_KEY] = counts
        return counts

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]:
        """Score how often this memory is a neighbour of the others.

        Args:
            candidate: The memory being scanned. Needs `candidate.id` and
                a stored `embedding`.
            context: The materialised batch in `context.existing`.

        Returns:
            One `Detection` with code `hub_record` when this record's
            k-occurrence is at or above the cutoff. Otherwise empty.
        """
        if candidate.id is None or not candidate.embedding:
            return []
        embedded = with_embeddings(context.existing)
        if len(embedded) < self.min_corpus:
            return []
        counts = self._counts(context)
        occurrence = counts.get(candidate.id, 0)
        if self.min_occurrence is not None:
            cutoff = self.min_occurrence
        else:
            cutoff = int(self.factor * self.k)
        if occurrence < cutoff:
            return []
        score = min(1.0, occurrence / max(cutoff, 1))
        return [
            self.hit(
                code="hub_record",
                score=score,
                k_occurrence=occurrence,
                k=self.k,
                cutoff=cutoff,
            )
        ]


__all__ = ["HubnessDetector"]
