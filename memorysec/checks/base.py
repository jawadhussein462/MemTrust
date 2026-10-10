"""The `MemoryCheck` base class.

Checks run one after another. Each check looks at one memory and returns
its own list of findings. Adding a check does not require editing the engine.
Every check runs when a store is scanned.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.finding import Finding
from ..models.memory import MemoryCandidate


class MemoryCheck:
    """One named check over a single memory.

    Set `name` and implement `check`. The built-in security checks subclass
    `SecurityCheck`, which subclasses this.

    Attributes:
        name: Label stored on each finding this check emits. The client uses
            it to replace a default check: a custom check named `"injection"`
            takes the place of the built-in injection check.
    """

    name: str = "base"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        """Inspect one memory and return every problem found.

        Args:
            candidate: The memory being scanned. Read `candidate.content`.
            context: Scan settings, the clock, neighbouring records, and the
                optional retrieval query.

        Returns:
            Findings for this memory. An empty list means this check found
            nothing. Never return `None`.

        Raises:
            NotImplementedError: Always, unless a subclass implements this.
        """
        raise NotImplementedError


__all__ = ["MemoryCheck"]
