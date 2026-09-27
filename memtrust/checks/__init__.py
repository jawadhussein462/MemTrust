"""Built-in checks and the check framework.

``default_checks()`` returns the standard pipeline. Additional checks can be
appended without modifying the engine.

Two families, each with a father class::

    BaseCheck
    ├── SecurityCheck        memtrust.checks.security
    │   ├── InjectionCheck     security/injection/   one detector class per method
    │   ├── PoisoningCheck     security/poisoning/
    │   └── SecretsCheck       security/secrets/
    └── CorrectnessCheck     memtrust.checks.correctness
        ├── ContradictionCheck
        ├── DuplicationCheck
        ├── FreshnessCheck
        └── GeneralizationCheck

Security checks are configured with detectors (heuristic by default; model
and hosted detectors opt-in). Passing a configured ``InjectionCheck`` /
``PoisoningCheck`` / ``SecretsCheck`` to ``MemTrust(checks=[...])`` replaces
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
from .correctness import (
    ContradictionCheck,
    CorrectnessCheck,
    DuplicationCheck,
    FreshnessCheck,
    GeneralizationCheck,
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
        FreshnessCheck(),
        DuplicationCheck(),
        ContradictionCheck(),
        GeneralizationCheck(),
    ]


__all__ = [
    "BaseCheck",
    "BaseDetector",
    "CheckFunction",
    "ContradictionCheck",
    "CorrectnessCheck",
    "Detection",
    "Detector",
    "DuplicationCheck",
    "FreshnessCheck",
    "FunctionCheck",
    "GeneralizationCheck",
    "InjectionCheck",
    "MemoryCheck",
    "PoisoningCheck",
    "SecretsCheck",
    "SecurityCheck",
    "check",
    "default_checks",
    "normalize_check",
]
