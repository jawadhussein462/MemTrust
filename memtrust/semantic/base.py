"""The :class:`SemanticAnalyzer` strategy interface.

Semantic comparison is a *strategy*: the deterministic heuristic analyzer is
always available and requires no network or API key, while an LLM-backed
analyzer can be swapped in for higher-quality relationship detection.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models.enums import MemoryRelationship
from ..models.memory import MemoryCandidate, MemoryRecord


@runtime_checkable
class SemanticAnalyzer(Protocol):
    """Compare an existing record with a candidate and classify the relationship."""

    name: str

    def compare(self, existing: MemoryRecord, candidate: MemoryCandidate) -> MemoryRelationship: ...


@runtime_checkable
class GeneralizationDetector(Protocol):
    """Optional capability: detect over-broad generalization of scoped facts.

    e.g. source says "for this migration, skip staging" but the candidate
    memory reads "user prefers skipping staging".
    """

    def detect_generalization(self, candidate: MemoryCandidate) -> bool: ...


__all__ = ["GeneralizationDetector", "MemoryRelationship", "SemanticAnalyzer"]
