"""Built-in checks and the check framework.

``default_checks()`` returns the standard pipeline. Additional checks can be
appended without modifying the engine.

Security checks are configured with detectors (heuristic by default; model
and hosted detectors opt-in). Passing a configured ``InjectionCheck`` /
``PoisoningCheck`` / ``SecretsCheck`` to ``MemorySec(checks=[...])`` replaces
the default check of the same name.
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
from .security import (
    BaseDetector,
    Detection,
    Detector,
    InjectionCheck,
    PoisoningCheck,
    SecretsCheck,
    SecurityCheck,
)


def default_checks() -> list[MemoryCheck]:
    """The default check pipeline, in execution order (offline, deterministic)."""
    return [
        SecretsCheck(),
        InjectionCheck(),
        PoisoningCheck(),
    ]


__all__ = [
    "BaseCheck",
    "BaseDetector",
    "CheckFunction",
    "Detection",
    "Detector",
    "FunctionCheck",
    "InjectionCheck",
    "MemoryCheck",
    "PoisoningCheck",
    "SecretsCheck",
    "SecurityCheck",
    "check",
    "default_checks",
    "normalize_check",
]
