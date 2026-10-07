"""Security checks: injection, poisoning, and secrets.

Layout::

    security/
      base.py          SecurityCheck (father class), Detector, Detection, FindingSpec
      injection/       InjectionCheck  + one detector per method
      poisoning/       PoisoningCheck  + one detector per method
      secrets/         SecretsCheck    + one detector per method

Each check runs a list of detectors and turns their detections into
findings. The defaults are the offline heuristics; model and hosted
detectors are opt-in::

    from memtrust import MemTrust
    from memtrust.checks.security import InjectionCheck
    from memtrust.checks.security.injection import (
        HeuristicInjectionDetector, PromptGuardDetector,
    )

    guard = MemTrust(checks=[
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
