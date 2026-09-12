"""Deterministic, offline semantic analyzer.

No network, no API key. Uses normalization, token overlap, relational
attribute-change detection, and polarity (negation) analysis, combined with
time to distinguish *supersession* (a newer version of a fact) from
*contradiction* (a genuine conflict). It is intentionally conservative and
imperfect — see ``SECURITY.md`` — but it makes MemTrust fully functional
with zero external dependencies.
"""

from __future__ import annotations

from ..models.enums import MemoryRelationship
from ..models.memory import MemoryCandidate, MemoryRecord
from ..text import jaccard, normalize, similarity, token_set, tokenize

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
    {"no", "not", "never", "without", "cannot", "cant", "dont", "doesnt", "isnt", "arent", "wont", "non"}
)

_TEMPORAL_MARKERS = ("now", "no longer", "currently", "as of", "updated", "anymore", "recently")

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


class HeuristicSemanticAnalyzer:
    """The default semantic analyzer."""

    name = "heuristic"

    def compare(self, existing: MemoryRecord, candidate: MemoryCandidate) -> MemoryRelationship:
        ne, nc = normalize(existing.content), normalize(candidate.content)
        if ne == nc:
            return MemoryRelationship.DUPLICATE

        # Different user partition => not a conflict, just different scope.
        if existing.scope.user_id != candidate.scope.user_id:
            return MemoryRelationship.DIFFERENT_SCOPE

        sim = similarity(existing.content, candidate.content)
        if sim >= 0.95:
            return MemoryRelationship.DUPLICATE

        newer = candidate.created_at > existing.created_at
        temporal = any(m in nc for m in _TEMPORAL_MARKERS)

        rel_change = self._relation_change(ne, nc)
        if rel_change:
            return (
                MemoryRelationship.SUPERSEDES
                if (newer or temporal)
                else MemoryRelationship.CONTRADICTS
            )

        if self._polarity_flip(ne, nc):
            return (
                MemoryRelationship.SUPERSEDES
                if (newer or temporal)
                else MemoryRelationship.CONTRADICTS
            )

        if sim >= 0.6:
            return MemoryRelationship.COMPATIBLE
        return MemoryRelationship.UNRELATED

    def detect_generalization(self, candidate: MemoryCandidate) -> bool:
        excerpt = candidate.source.excerpt or ""
        if not excerpt:
            return False
        nsrc = normalize(excerpt)
        ncontent = normalize(candidate.content)
        has_limiter = any(limiter in nsrc for limiter in _LIMITERS)
        is_generalized = any(gen in ncontent for gen in _GENERALIZERS)
        return has_limiter and is_generalized

    # -- internals --------------------------------------------------------------

    def _relation_change(self, ne: str, nc: str) -> bool:
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

    def _polarity_flip(self, ne: str, nc: str) -> bool:
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


__all__ = ["HeuristicSemanticAnalyzer"]
