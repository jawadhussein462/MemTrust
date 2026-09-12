"""Contradiction and supersession, via the pluggable semantic analyzer.

Correctness is not reduced to similarity. Using time, a newer fact
*supersedes* an old one (history preserved), whereas a genuine conflict is
flagged for review.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, Category, MemoryRelationship, MemoryStatus, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate, MemoryRecord
from ..base import BaseCheck


def _comparable(existing: MemoryRecord) -> bool:
    return existing.status == MemoryStatus.ACTIVE


class ContradictionCheck(BaseCheck):
    """Classify candidate-vs-existing relationships and act accordingly."""

    name = "contradiction"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        if not context.config.contradiction_enabled:
            return []

        findings: list[Finding] = []
        for existing in context.existing:
            if not _comparable(existing):
                continue
            rel = context.semantic.compare(existing, candidate)

            if rel == MemoryRelationship.SUPERSEDES:
                findings.append(
                    Finding(
                        code="supersedes_existing",
                        category=Category.CORRECTNESS,
                        severity=Severity.LOW,
                        message=f"Candidate is a newer version of memory '{existing.id}'.",
                        evidence={"supersedes": [existing.id]},
                        check=self.name,
                        recommended_action=Action.SUPERSEDE,
                    )
                )
            elif rel == MemoryRelationship.CONTRADICTS:
                findings.append(
                    Finding(
                        code="contradiction",
                        category=Category.CORRECTNESS,
                        severity=Severity.MEDIUM,
                        message=f"Candidate conflicts with existing memory '{existing.id}'.",
                        evidence={"conflicts_with": existing.id},
                        check=self.name,
                        recommended_action=Action.REVIEW,
                    )
                )
        return findings


__all__ = ["ContradictionCheck"]
