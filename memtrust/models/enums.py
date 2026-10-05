"""Enumerations used across MemTrust.

All enums subclass ``StrEnum`` so they serialize cleanly to JSON and compare
equal to their string values (``Severity.HIGH == "high"``). Where an
ordering is meaningful (severity, risk) a ``rank`` property and an
``is_at_least`` helper are provided rather than overriding comparison
operators, which would be ambiguous on a ``str`` subclass.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Severity of an individual :class:`~memtrust.Finding`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    def is_at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Risk(StrEnum):
    """Overall risk of a :class:`~memtrust.Decision` (worst finding)."""

    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_ORDER[self]

    @classmethod
    def from_severity(cls, severity: Severity) -> Risk:
        return cls(severity.value)


_RISK_ORDER: dict[Risk, int] = {
    Risk.NONE: 0,
    Risk.INFO: 1,
    Risk.LOW: 2,
    Risk.MEDIUM: 3,
    Risk.HIGH: 4,
    Risk.CRITICAL: 5,
}


class Category(StrEnum):
    """The concern a finding relates to. Built-in checks are security only."""

    SECURITY = "security"


class Action(StrEnum):
    """What MemTrust recommends doing with a candidate or record.

    Scan reports use ``review``, ``quarantine``, or ``delete``. Ordered by
    "blocking-ness" via :attr:`precedence` so that when several checks
    disagree the most protective action wins.
    """

    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    REVIEW = "review"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    BLOCK = "block"

    @property
    def precedence(self) -> int:
        """Higher precedence wins when aggregating findings."""
        return _ACTION_PRECEDENCE[self]

    @property
    def is_allowed(self) -> bool:
        """Whether this action lets the underlying operation proceed."""
        return self in _ALLOWED_ACTIONS


_ACTION_PRECEDENCE: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.ALLOW_WITH_WARNING: 1,
    Action.REVIEW: 2,
    Action.QUARANTINE: 3,
    Action.DELETE: 4,
    Action.BLOCK: 5,
}

_ALLOWED_ACTIONS: frozenset[Action] = frozenset({Action.ALLOW, Action.ALLOW_WITH_WARNING})


class MemoryStatus(StrEnum):
    """Lifecycle state of a persisted :class:`~memtrust.MemoryRecord`."""

    ACTIVE = "active"
    REVOKED = "revoked"
    QUARANTINED = "quarantined"


__all__ = [
    "Action",
    "Category",
    "MemoryStatus",
    "Risk",
    "Severity",
]
