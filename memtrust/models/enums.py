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
    """The concern a finding relates to.

    MemTrust is oriented around two families of checks:

    * **security** — poisoning, injection, secrets
    * **correctness** — contradictions, duplicates, freshness, generalization
    """

    SECURITY = "security"
    CORRECTNESS = "correctness"


class Action(StrEnum):
    """What MemTrust recommends doing with a candidate or record.

    Ordered by "blocking-ness" via :attr:`precedence` so that when several
    checks disagree the most protective action wins.
    """

    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    SUPERSEDE = "supersede"
    REWRITE = "rewrite"
    REVIEW = "review"
    QUARANTINE = "quarantine"
    BLOCK = "block"

    @property
    def precedence(self) -> int:
        """Higher precedence wins when aggregating findings."""
        return _ACTION_PRECEDENCE[self]

    @property
    def is_allowed(self) -> bool:
        """Whether this action lets the underlying operation proceed."""
        return self in _ALLOWED_ACTIONS


# Precedence: block > quarantine > review > rewrite > supersede > warn > allow
_ACTION_PRECEDENCE: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.ALLOW_WITH_WARNING: 1,
    Action.SUPERSEDE: 2,
    Action.REWRITE: 3,
    Action.REVIEW: 4,
    Action.QUARANTINE: 5,
    Action.BLOCK: 6,
}

_ALLOWED_ACTIONS: frozenset[Action] = frozenset(
    {Action.ALLOW, Action.ALLOW_WITH_WARNING, Action.SUPERSEDE, Action.REWRITE}
)


class MemoryStatus(StrEnum):
    """Lifecycle state of a persisted :class:`~memtrust.MemoryRecord`."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"
    QUARANTINED = "quarantined"
    EXPIRED = "expired"


class MemoryRelationship(StrEnum):
    """How a candidate memory relates to an existing one.

    Correctness is *not* reduced to embedding similarity: relationships are
    modelled explicitly so that, for example, a newer fact can ``SUPERSEDE``
    an older one instead of merely ``CONTRADICTS`` it.
    """

    DUPLICATE = "duplicate"
    COMPATIBLE = "compatible"
    CONTRADICTS = "contradicts"
    SUPERSEDES = "supersedes"
    SPECIALIZES = "specializes"
    UNRELATED = "unrelated"


class Mode(StrEnum):
    """Enforcement mode for a :class:`~memtrust.MemTrust` instance.

    ``observe`` reports violations but never changes backend behaviour;
    ``warn`` allows operations but downgrades blocking actions to warnings;
    ``enforce`` (the default) applies the recommended action.
    """

    OBSERVE = "observe"
    WARN = "warn"
    ENFORCE = "enforce"


class AuditEventType(StrEnum):
    """Types of events recorded in the audit trail."""

    WRITE_REQUESTED = "WRITE_REQUESTED"
    WRITE_ALLOWED = "WRITE_ALLOWED"
    WRITE_BLOCKED = "WRITE_BLOCKED"
    WRITE_QUARANTINED = "WRITE_QUARANTINED"
    READ_REQUESTED = "READ_REQUESTED"
    READ_ALLOWED = "READ_ALLOWED"
    READ_FILTERED = "READ_FILTERED"
    MEMORY_SUPERSEDED = "MEMORY_SUPERSEDED"
    MEMORY_REVOKED = "MEMORY_REVOKED"


__all__ = [
    "Action",
    "AuditEventType",
    "Category",
    "MemoryRelationship",
    "MemoryStatus",
    "Mode",
    "Risk",
    "Severity",
]
