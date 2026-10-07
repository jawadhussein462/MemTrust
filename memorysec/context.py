"""The :class:`CheckContext` passed to every check.

Bundles everything a check needs to reason about a candidate without giving
it the ability to mutate global state or perform I/O. Checks are pure:
``(candidate, context) -> list[Finding]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .config import Config
from .models.memory import MemoryRecord


@dataclass
class CheckContext:
    """Read-only context for scanning one record."""

    config: Config
    now: datetime
    operation: str = "scan"
    # Other records in the scanned batch, when the caller passed a sequence.
    # Retrieval-aware detectors (TrustRAG) use this; streaming scans leave it empty.
    existing: list[MemoryRecord] = field(default_factory=list)
    # The retrieval query, when the caller passes ``MemTrust.scan(..., query=)``
    # or the record metadata carries one. FilterRAG uses it; most checks ignore it.
    query: str | None = None


__all__ = ["CheckContext"]
