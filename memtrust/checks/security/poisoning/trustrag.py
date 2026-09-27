"""TrustRAG clean-retrieval stage: coordinated poison forms a tight cluster.

From *TrustRAG: Enhancing Robustness and Trustworthiness in RAG*
(arXiv:2501.00879). Attackers who inject several passages for one target
query optimise them all toward the same query and answer, so the poisoned
passages sit unusually close together in embedding space (pairwise cosine
>= 0.85 in the paper) *and* share unusually many n-grams (ROUGE-L >= 0.25,
the "n-gram preservation" rule that keeps merely topical clean documents).
A single poisoned passage is dispersed among clean ones and is not caught
here; that is what the content detectors are for.

Applied to memory: a candidate is suspicious when at least ``min_cluster``
of its neighbours -- the records the backend retrieved alongside it
(``context.existing``: write-time neighbours, or the rest of the read set)
-- are near-paraphrases of it. Pass ``embed`` (``list[str] -> list[vector]``)
to use cosine similarity as in the paper; without it MemTrust's lexical
similarity stands in for the embedding test, with the same threshold.
Legitimate copies of the same fact trigger this too, which is why the
finding asks for review rather than quarantine.
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
    """Flag candidates that belong to a tight near-paraphrase cluster of neighbours."""

    name = "trustrag"

    def __init__(
        self,
        *,
        embed: Embed | None = None,
        cosine_threshold: float = 0.85,
        rouge_threshold: float = 0.25,
        min_cluster: int = 2,
    ) -> None:
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
