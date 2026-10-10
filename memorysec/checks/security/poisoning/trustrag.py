"""TrustRAG: coordinated poison shows up as a tight cluster of near-copies.

From TrustRAG (Zhou et al., arXiv:2501.00879). An attacker who plants
several passages for one question pushes them all toward the same query
and answer, so the poisoned passages sit close together in embedding space
(pairwise cosine at least 0.85 in the paper) and share many word sequences
(ROUGE-L at least 0.25). That second test keeps ordinary documents on the
same topic from counting. One poisoned passage sitting among clean ones
is not caught here.

Applied to memory: a candidate is suspicious when at least `min_cluster`
neighbours are near-paraphrases of it. Neighbours come from the scanned
batch (`context.existing`).

Search order:

1. Stored vectors, via cosine nearest-neighbour (the store already has them).
2. An `embed` callback, then the same nearest-neighbour cut.
3. Lexical similarity, only when the batch is at most `max_pairwise`
   records. Larger batches without vectors are skipped rather than doing
   O(n²) Python string compares.

Pass `embed`, a function `(texts) -> vectors`, when the records have no
stored embeddings. Real copies of the same fact trigger this too, so the
finding asks for review rather than quarantine.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ....context import CheckContext
from ....exceptions import ConfigurationError
from ....models.memory import MemoryCandidate, MemoryRecord
from ....text import cosine, rouge_l, similarity
from ....vectors import nearest
from ..base import BaseDetector, Detection
from ._corpus import active_neighbours

Embed = Callable[[Sequence[str]], Sequence[Sequence[float]]]


class TrustRAGDetector(BaseDetector):
    """Flag a memory that has several near-copy neighbours.

    The finding code is `poisoning_cluster`. A one-record scan has no
    neighbours, so this detector returns nothing for it.
    """

    name = "trustrag"

    def __init__(
        self,
        *,
        embed: Embed | None = None,
        cosine_threshold: float = 0.85,
        rouge_threshold: float = 0.25,
        min_cluster: int = 2,
        nn: int = 32,
        max_pairwise: int = 2000,
    ) -> None:
        """Store the cluster thresholds. No model is loaded here.

        Args:
            embed: Function `(texts) -> one vector per text`. Used when the
                candidate and its neighbours have no stored embeddings.
            cosine_threshold: Minimum similarity with a neighbour, from just
                above 0 to 1. Default `0.85`, the paper's cutoff. Also used
                as the lexical cutoff when neither stored vectors nor
                `embed` are available.
            rouge_threshold: Minimum ROUGE-L overlap with a neighbour, from
                just above 0 to 1. Default `0.25`.
            min_cluster: How many neighbours must pass both tests. Default
                `2`. Must be at least 1.
            nn: How many nearest neighbours to inspect when vectors are
                available. Default `32`.
            max_pairwise: Largest batch that may fall back to lexical
                pairwise compares. Larger batches without vectors are
                skipped. Default `2000`.

        Raises:
            ConfigurationError: A threshold is outside (0, 1], or
                `min_cluster` / `nn` / `max_pairwise` is below 1.
        """
        if not 0.0 < cosine_threshold <= 1.0 or not 0.0 < rouge_threshold <= 1.0:
            raise ConfigurationError("thresholds must be within (0, 1].")
        if min_cluster < 1:
            raise ConfigurationError("min_cluster must be >= 1.")
        if nn < 1:
            raise ConfigurationError("nn must be >= 1.")
        if max_pairwise < 1:
            raise ConfigurationError("max_pairwise must be >= 1.")
        self.embed = embed
        self.cosine_threshold = cosine_threshold
        self.rouge_threshold = rouge_threshold
        self.min_cluster = min_cluster
        self.nn = nn
        self.max_pairwise = max_pairwise

    def _ranked(
        self, candidate: MemoryCandidate, neighbours: Sequence[MemoryRecord]
    ) -> tuple[list[tuple[MemoryRecord, float]], str]:
        if candidate.embedding and any(n.embedding for n in neighbours):
            ranked = nearest(
                candidate.embedding,
                neighbours,
                k=min(self.nn, len(neighbours)),
                exclude_id=candidate.id,
                active_only=False,
            )
            return ranked, "stored"
        if self.embed is not None:
            vectors = self.embed([candidate.content, *(n.content for n in neighbours)])
            if len(vectors) != len(neighbours) + 1:
                raise ConfigurationError("embed() must return one vector per input text.")
            anchor = list(vectors[0])
            scored = [
                (record, cosine(anchor, list(vector)))
                for record, vector in zip(neighbours, vectors[1:], strict=True)
            ]
            scored.sort(key=lambda item: item[1], reverse=True)
            return scored[: min(self.nn, len(scored))], "cosine"
        if len(neighbours) > self.max_pairwise:
            return [], "skipped"
        scored = [(record, similarity(candidate.content, record.content)) for record in neighbours]
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored, "lexical"

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
        neighbours = active_neighbours(candidate, context)
        if len(neighbours) < self.min_cluster:
            return []
        ranked, metric = self._ranked(candidate, neighbours)
        if not ranked:
            return []
        cluster: list[tuple[str, float, float]] = []
        for record, sim in ranked:
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
                similarity_metric=metric,
                min_similarity=round(min(s for _, s, _ in cluster), 3),
                min_rouge_l=round(min(r for _, _, r in cluster), 3),
            )
        ]


__all__ = ["TrustRAGDetector"]
