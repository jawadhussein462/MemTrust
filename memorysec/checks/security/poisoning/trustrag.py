"""TrustRAG: coordinated poison shows up as a tight cluster of near-copies.

From TrustRAG (arXiv:2501.00879). An attacker who plants several passages
for one question pushes them all toward the same query and answer, so the
poisoned passages sit close together in embedding space (pairwise cosine
at least 0.85 in the paper) and share many word sequences (ROUGE-L at
least 0.25). That second test keeps ordinary documents on the same topic
from counting. One poisoned passage sitting among clean ones is not caught
here. The phrase detectors are for that case.

Applied to memory: a candidate is suspicious when at least `min_cluster`
neighbours are near-paraphrases of it. Neighbours are the other records in
the scanned batch (`context.existing`).

Pass `embed`, a function `(texts) -> vectors`, to use cosine similarity as
in the paper. Without it, lexical similarity is used with the same threshold.
Real copies of the same fact trigger this too, so the finding asks for
review rather than quarantine.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ....context import CheckContext
from ....exceptions import ConfigurationError
from ....models.enums import MemoryStatus
from ....models.memory import MemoryCandidate, MemoryRecord
from ....text import cosine, rouge_l, similarity
from ..base import BaseDetector, Detection

Embed = Callable[[Sequence[str]], Sequence[Sequence[float]]]


class TrustRAGDetector(BaseDetector):
    """Flag a memory that has several near-copy neighbours.

    The finding code is `poisoning_cluster`. Streaming scans have no
    neighbours, so this detector returns nothing for them.
    """

    name = "trustrag"

    def __init__(
        self,
        *,
        embed: Embed | None = None,
        cosine_threshold: float = 0.85,
        rouge_threshold: float = 0.25,
        min_cluster: int = 2,
    ) -> None:
        """Store the cluster thresholds. No model is loaded here.

        Args:
            embed: Function `(texts) -> one vector per text`. The first text
                is the candidate and the rest are neighbours. `None` uses
                lexical similarity instead of cosine.
            cosine_threshold: Minimum similarity with a neighbour, from just
                above 0 to 1. Default `0.85`, the paper's cutoff. Also used
                as the lexical cutoff when `embed` is omitted.
            rouge_threshold: Minimum ROUGE-L overlap with a neighbour, from
                just above 0 to 1. Default `0.25`.
            min_cluster: How many neighbours must pass both tests. Default
                `2`. Must be at least 1.

        Raises:
            ConfigurationError: A threshold is outside (0, 1], or
                `min_cluster` is below 1.
        """
        if not 0.0 < cosine_threshold <= 1.0 or not 0.0 < rouge_threshold <= 1.0:
            raise ConfigurationError("thresholds must be within (0, 1].")
        if min_cluster < 1:
            raise ConfigurationError("min_cluster must be >= 1.")
        self.embed = embed
        self.cosine_threshold = cosine_threshold
        self.rouge_threshold = rouge_threshold
        self.min_cluster = min_cluster

    def _neighbours(self, candidate: MemoryCandidate, context: CheckContext) -> list[MemoryRecord]:
        return [
            record
            for record in context.existing
            if record.status == MemoryStatus.ACTIVE
            and (candidate.id is None or record.id != candidate.id)
        ]

    def _embedding_scores(self, text: str, neighbours: Sequence[MemoryRecord]) -> list[float]:
        if self.embed is None:
            return [similarity(text, n.content) for n in neighbours]
        vectors = self.embed([text, *(n.content for n in neighbours)])
        if len(vectors) != len(neighbours) + 1:
            raise ConfigurationError("embed() must return one vector per input text.")
        anchor = list(vectors[0])
        return [cosine(anchor, list(v)) for v in vectors[1:]]

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]:
        """Look for a near-copy cluster around this memory.

        Args:
            candidate: The memory being scanned.
            context: Must include `context.existing`, the other records in
                the batch. Inactive records and the candidate itself are
                skipped.

        Returns:
            One `Detection` with code `poisoning_cluster` when at least
            `min_cluster` neighbours are close enough. Otherwise an empty list.

        Raises:
            ConfigurationError: `embed` did not return one vector per text.
        """
        neighbours = self._neighbours(candidate, context)
        if len(neighbours) < self.min_cluster:
            return []
        scores = self._embedding_scores(candidate.content, neighbours)
        cluster: list[tuple[str, float, float]] = []
        for record, sim in zip(neighbours, scores, strict=True):
            if sim < self.cosine_threshold:
                continue
            overlap = rouge_l(candidate.content, record.content)
            if overlap >= self.rouge_threshold:
                cluster.append((record.id, sim, overlap))
        if len(cluster) < self.min_cluster:
            return []
        cluster.sort(key=lambda item: -item[1])
        return [
            self.hit(
                code="poisoning_cluster",
                score=min(1.0, sum(s for _, s, _ in cluster) / len(cluster)),
                cluster=[rid for rid, _, _ in cluster],
                cluster_size=len(cluster),
                similarity_metric="cosine" if self.embed is not None else "lexical",
                min_similarity=round(min(s for _, s, _ in cluster), 3),
                min_rouge_l=round(min(r for _, _, r in cluster), 3),
            )
        ]


__all__ = ["TrustRAGDetector"]
