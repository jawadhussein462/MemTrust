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
    """Read-only context for a single write or read evaluation."""

    config: Config
    now: datetime
    operation: str = "write"  # "write" | "read"
    existing: list[MemoryRecord] = field(default_factory=list)


__all__ = ["CheckContext"]
