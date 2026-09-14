"""Detect over-broad generalization of narrowly-scoped facts.

Example: a source note "for this migration, skip staging" becomes a persisted
memory "user prefers skipping staging". The narrow, one-off instruction has
been wrongly generalized into a standing preference.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ...text import normalize
from ..base import BaseCheck

_LIMITERS = (
    "for this",
    "this time",
    "just this once",
    "for the migration",
    "temporarily",
    "right now",
    "today",
    "this once",
    "for now",
    "one time",
    "this case",
    "in this instance",
)
_GENERALIZERS = ("prefers", "prefer", "always", "usually", "in general", "by default", "generally")


def _is_over_generalized(candidate: MemoryCandidate) -> bool:
    excerpt = candidate.excerpt or ""
    if not excerpt:
        return False
    nsrc = normalize(excerpt)
    ncontent = normalize(candidate.content)
    has_limiter = any(limiter in nsrc for limiter in _LIMITERS)
    is_generalized = any(gen in ncontent for gen in _GENERALIZERS)
    return has_limiter and is_generalized


class GeneralizationCheck(BaseCheck):
    """Flag candidates that over-generalize a scoped source instruction."""

    name = "generalization"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        if not _is_over_generalized(candidate):
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
                evidence={"excerpt": (candidate.excerpt or "")[:200]},
                check=self.name,
                recommended_action=Action.REVIEW,
            )
        ]


__all__ = ["GeneralizationCheck"]
