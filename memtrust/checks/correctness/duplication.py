"""Local duplicate detection (no embeddings required).

Uses normalization plus fuzzy string/token similarity against the existing
records supplied in the context. This is deliberately simple and local.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, MemoryStatus, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate, MemoryRecord
from ...text import similarity, value_change
from .base import CorrectnessCheck


def _active(existing: MemoryRecord) -> bool:
    return existing.status == MemoryStatus.ACTIVE


class DuplicationCheck(CorrectnessCheck):
    """Flag a candidate that closely duplicates an existing active memory."""

    name = "duplication"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        threshold = context.config.duplicate_threshold
        best_id: str | None = None
        best_score = 0.0
        for existing in context.existing:
            # A changed number is an update, not a duplicate (ContradictionCheck owns it).
            if not _active(existing) or value_change(existing.content, candidate.content):
                continue
            score = similarity(candidate.content, existing.content)
            if score > best_score:
                best_score, best_id = score, existing.id

        if best_id is not None and best_score >= threshold:
            return [
                self.finding(
                    "duplicate_memory",
                    severity=Severity.LOW,
                    action=Action.ALLOW_WITH_WARNING,
                    message=(
                        f"Candidate is ~{best_score:.0%} similar to existing memory '{best_id}'."
                    ),
                    evidence={"duplicate_of": best_id, "similarity": round(best_score, 3)},
                )
            ]
        return []


__all__ = ["DuplicationCheck"]
