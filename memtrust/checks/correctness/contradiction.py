"""Contradiction and supersession against existing memories.

Correctness is not reduced to similarity. Using time, a newer fact
*supersedes* an old one (history preserved), whereas a genuine conflict is
flagged for review.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, Category, MemoryRelationship, MemoryStatus, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate, MemoryRecord
from ...text import jaccard, normalize, similarity, token_set, tokenize, value_change
from ..base import BaseCheck

# Relational phrases whose object commonly changes over time.
_RELATIONS = [
    "works at",
    "work at",
    "working at",
    "works for",
    "lives in",
    "based in",
    "located in",
    "reports to",
    "prefers",
    "uses",
    "email is",
    "phone is",
    "role is",
    "title is",
    "is a",
    "is the",
]

_NEGATORS = frozenset(
    {
        "no",
        "not",
        "never",
        "without",
        "cannot",
        "cant",
        "dont",
        "doesnt",
        "isnt",
        "arent",
        "wont",
        "non",
    }
)

_TEMPORAL_MARKERS = ("now", "no longer", "currently", "as of", "updated", "anymore", "recently")


def _comparable(existing: MemoryRecord) -> bool:
    return existing.status == MemoryStatus.ACTIVE


def _relation_change(ne: str, nc: str) -> bool:
    """True if both mention the same subject+relation but different objects."""
    for rel in _RELATIONS:
        token = f" {rel} "
        padded_e, padded_c = f" {ne} ", f" {nc} "
        if token in padded_e and token in padded_c:
            e_before, e_after = padded_e.split(token, 1)
            c_before, c_after = padded_c.split(token, 1)
            subject_same = jaccard(e_before, c_before) >= 0.5
            object_changed = similarity(e_after, c_after) < 0.6
            if subject_same and object_changed:
                return True
    return False


def _polarity_flip(ne: str, nc: str) -> bool:
    """True if two similar statements have opposite negation parity."""
    base_e = token_set(ne) - _NEGATORS
    base_c = token_set(nc) - _NEGATORS
    if not base_e or not base_c:
        return False
    overlap = len(base_e & base_c) / len(base_e | base_c)
    if overlap < 0.6:
        return False
    parity_e = sum(1 for t in tokenize(ne) if t in _NEGATORS) % 2
    parity_c = sum(1 for t in tokenize(nc) if t in _NEGATORS) % 2
    if parity_e != parity_c:
        return True
    return ("no longer" in nc) != ("no longer" in ne)


def _relate(existing: MemoryRecord, candidate: MemoryCandidate) -> MemoryRelationship:
    ne, nc = normalize(existing.content), normalize(candidate.content)
    if ne == nc:
        return MemoryRelationship.DUPLICATE

    newer = candidate.created_at > existing.created_at
    temporal = any(m in nc for m in _TEMPORAL_MARKERS)

    # Same statement, different number: checked before the near-duplicate
    # test because "limit is 100 rps" / "limit is 500 rps" is ~95% similar.
    if value_change(existing.content, candidate.content):
        return (
            MemoryRelationship.SUPERSEDES if (newer or temporal) else MemoryRelationship.CONTRADICTS
        )

    sim = similarity(existing.content, candidate.content)
    if sim >= 0.95:
        return MemoryRelationship.DUPLICATE

    if _relation_change(ne, nc):
        return (
            MemoryRelationship.SUPERSEDES if (newer or temporal) else MemoryRelationship.CONTRADICTS
        )

    if _polarity_flip(ne, nc):
        return (
            MemoryRelationship.SUPERSEDES if (newer or temporal) else MemoryRelationship.CONTRADICTS
        )

    if sim >= 0.6:
        return MemoryRelationship.COMPATIBLE
    return MemoryRelationship.UNRELATED


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
            rel = _relate(existing, candidate)

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
