"""Security checks: injection, poisoning, and secrets.

Layout:

    security/
      base.py       SecurityCheck, Detector, Detection, FindingSpec
      injection/    InjectionCheck and one detector per method
      poisoning/    PoisoningCheck and one detector per method
      secrets/      SecretsCheck and one detector per method

Each check runs detectors and turns their hits into findings. The defaults
are offline heuristics. Model and hosted detectors are optional.

Example:
    Replace the default injection check with heuristic plus Prompt Guard::

        from memorysec import MemorySec
        from memorysec.checks.security import InjectionCheck
        from memorysec.checks.security.injection import (
            HeuristicInjectionDetector, PromptGuardDetector,
        )

        guard = MemorySec(checks=[
            InjectionCheck(detectors=[HeuristicInjectionDetector(), PromptGuardDetector()]),
        ])
"""

from __future__ import annotations

from .base import BaseDetector, Detection, Detector, FindingSpec, SecurityCheck
from .injection import InjectionCheck
from .poisoning import PoisoningCheck
from .secrets import SecretsCheck

__all__ = [
    "BaseDetector",
    "Detection",
    "Detector",
    "FindingSpec",
    "InjectionCheck",
    "PoisoningCheck",
    "SecretsCheck",
    "SecurityCheck",
]
