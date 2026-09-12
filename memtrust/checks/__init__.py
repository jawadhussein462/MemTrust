"""Built-in checks and the check framework.

``default_checks()`` returns the standard pipeline. Additional checks can be
appended without modifying the engine.

Security checks detect poisoning, injection, and secrets.
Correctness checks detect contradictions, duplicates, freshness, and
over-generalization.
"""

from __future__ import annotations

from .base import (
    BaseCheck,
    CheckFunction,
    FunctionCheck,
    MemoryCheck,
    check,
    normalize_check,
)
from .correctness import (
    ContradictionCheck,
    DuplicationCheck,
    FreshnessCheck,
    GeneralizationCheck,
)
from .security import InjectionCheck, PoisoningCheck, SecretsCheck


def default_checks() -> list[MemoryCheck]:
    """The default write-check pipeline, in execution order."""
    return [
        SecretsCheck(),
        InjectionCheck(),
        PoisoningCheck(),
        FreshnessCheck(),
        DuplicationCheck(),
        ContradictionCheck(),
        GeneralizationCheck(),
    ]


__all__ = [
    "BaseCheck",
    "CheckFunction",
    "ContradictionCheck",
    "DuplicationCheck",
    "FreshnessCheck",
    "FunctionCheck",
    "GeneralizationCheck",
    "InjectionCheck",
    "MemoryCheck",
    "PoisoningCheck",
    "SecretsCheck",
    "check",
    "default_checks",
    "normalize_check",
]
