"""Local duplicate detection (no embeddings required).

Uses normalization plus fuzzy string/token similarity against the existing
records supplied in the context. This is deliberately simple and local.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, Category, MemoryStatus, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate, MemoryRecord
from ...text import similarity, value_change
from ..base import BaseCheck


def _active(existing: MemoryRecord) -> bool:
    return existing.status == MemoryStatus.ACTIVE


class DuplicationCheck(BaseCheck):
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
                Finding(
                    code="duplicate_memory",
                    category=Category.CORRECTNESS,
                    severity=Severity.LOW,
                    message=(
                        f"Candidate is ~{best_score:.0%} similar to existing memory '{best_id}'."
                    ),
                    evidence={"duplicate_of": best_id, "similarity": round(best_score, 3)},
                    check=self.name,
                    recommended_action=Action.ALLOW_WITH_WARNING,
                )
            ]
        return []


__all__ = ["DuplicationCheck"]
