"""NLI contradiction plus time ordering.

Related to A-MemGuard's consensus validation (Wei et al., arXiv:2510.02373).
For each record, run a natural-language-inference model against its
nearest neighbours. A newer record that contradicts older established
ones is flagged as suspected poisoning. This is the method that can
catch fluent false facts such as "the refund policy was updated…",
which no regex will see.

Needs stored embeddings (to pick neighbours) or falls back to the first
`max_compare` active neighbours, plus an `nli` callback
`(premise, hypothesis) -> {label: score}`. Without `nli` this detector
returns nothing. A typical callback wraps
`cross-encoder/nli-deberta-v3-base`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ....context import CheckContext
from ....exceptions import ConfigurationError
from ....models.memory import MemoryCandidate, MemoryRecord
from ....vectors import nearest
from ..base import BaseDetector, Detection
from ._corpus import active_neighbours

NLI = Callable[[str, str], Mapping[str, float]]


class TemporalNLIDetector(BaseDetector):
    """Flag a newer memory that contradicts older neighbours.

    The finding code is `temporal_contradiction`.
    """

    name = "temporal_nli"

    def __init__(
        self,
        *,
        nli: NLI | None = None,
        contradiction_threshold: float = 0.8,
        min_older: int = 1,
        nn: int = 8,
        max_compare: int = 8,
    ) -> None:
        """Store the NLI callback and the contradiction cutoff.

        Args:
            nli: Function `(premise, hypothesis) -> label scores`. Labels
                should include `"contradiction"` (case-insensitive). `None`
                disables the detector.
            contradiction_threshold: Minimum contradiction score. Default
                `0.8`. Must be within (0, 1].
            min_older: How many older neighbours must contradict the
                candidate. Default `1`.
            nn: Neighbours to inspect when embeddings are present.
            max_compare: Neighbours to inspect when embeddings are missing.

        Raises:
            ConfigurationError: A threshold or count is out of range.
        """
        if not 0.0 < contradiction_threshold <= 1.0:
            raise ConfigurationError("contradiction_threshold must be within (0, 1].")
        if min_older < 1:
            raise ConfigurationError("min_older must be >= 1.")
        if nn < 1 or max_compare < 1:
            raise ConfigurationError("nn and max_compare must be >= 1.")
        self.nli = nli
        self.contradiction_threshold = contradiction_threshold
        self.min_older = min_older
        self.nn = nn
        self.max_compare = max_compare

    def _neighbours(
        self, candidate: MemoryCandidate, context: CheckContext
    ) -> list[MemoryRecord]:
        neighbours = active_neighbours(candidate, context)
        older = [record for record in neighbours if record.created_at < candidate.created_at]
        if candidate.embedding and any(record.embedding for record in older):
            ranked = nearest(
                candidate.embedding,
                older,
                k=min(self.nn, len(older)),
                exclude_id=candidate.id,
                active_only=False,
            )
            return [record for record, _score in ranked]
        older.sort(key=lambda record: record.created_at)
        return older[: self.max_compare]

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]:
        """Ask whether older neighbours contradict this memory.

        Args:
            candidate: The newer claim. `created_at` is compared with
                each neighbour.
            context: The materialised batch in `context.existing`.

        Returns:
            One `Detection` with code `temporal_contradiction` when at
            least `min_older` older neighbours contradict the candidate.
            Empty when `nli` is missing or there are no older neighbours.
        """
        if self.nli is None:
            return []
        older = self._neighbours(candidate, context)
        if len(older) < self.min_older:
            return []
        hits: list[tuple[str, float]] = []
        for record in older:
            raw = self.nli(record.content, candidate.content)
            scores = {str(k).lower(): float(v) for k, v in raw.items()}
            contradiction = scores.get("contradiction", 0.0)
            if contradiction >= self.contradiction_threshold:
                hits.append((record.id, contradiction))
        if len(hits) < self.min_older:
            return []
        hits.sort(key=lambda item: -item[1])
        return [
            self.hit(
                code="temporal_contradiction",
                score=hits[0][1],
                contradicted_by=[rid for rid, _ in hits],
                contradiction=round(hits[0][1], 3),
            )
        ]


__all__ = ["TemporalNLIDetector"]
