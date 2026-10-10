"""Check framework: the :class:`MemoryCheck` base class.

Checks form a pipeline. Each check is independent and returns a list of
findings; adding a new check never requires editing the engine. Every check
runs when a store is scanned.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.finding import Finding
from ..models.memory import MemoryCandidate


class MemoryCheck:
    """Base class for a named check over a candidate memory.

    Subclasses set ``name`` and implement :meth:`check`. Built-in security
    concerns subclass :class:`~memorysec.checks.security.SecurityCheck`, which
    itself subclasses this.
    """

    name: str = "base"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        raise NotImplementedError


__all__ = ["MemoryCheck"]
