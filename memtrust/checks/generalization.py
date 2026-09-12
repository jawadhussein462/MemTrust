"""Detect over-broad generalization of narrowly-scoped facts.

Example: a source note "for this migration, skip staging" becomes a persisted
memory "user prefers skipping staging". The narrow, one-off instruction has
been wrongly generalized into a standing preference.

This is exposed as an extension point: the actual detection is delegated to
the semantic analyzer's optional ``detect_generalization`` capability, so it
can start heuristic and later become model-backed without changing the check.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, Severity
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from .base import BaseCheck


class GeneralizationCheck(BaseCheck):
    """Flag candidates that over-generalize a scoped source instruction."""

    name = "generalization"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        detector = getattr(context.semantic, "detect_generalization", None)
        if detector is None:
            return []
        try:
            flagged = bool(detector(candidate))
        except Exception:
            return []
        if not flagged:
            return []
        return [
            Finding(
                code="bad_generalization",
                category=Category.CORRECTNESS,
                severity=Severity.MEDIUM,
                message=(
                    "Candidate appears to generalize a narrowly-scoped, one-off instruction "
                    "into a standing fact/preference."
                ),
                evidence={"source_excerpt": (candidate.source.excerpt or "")[:200]},
                check=self.name,
                recommended_action=Action.REVIEW,
            )
        ]


__all__ = ["GeneralizationCheck"]
