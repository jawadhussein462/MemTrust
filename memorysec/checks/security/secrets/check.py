"""The secrets check: credentials, keys, tokens -- and, opt-in, personal data."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicSecretsDetector


class SecretsCheck(SecurityCheck):
    """Refuse secret-bearing content; optionally flag personal data for review.

    Findings never contain the raw value -- only the kinds detected.
    Defaults to the offline heuristic detector; stack entropy or model
    detectors for formats it has no pattern for::

        SecretsCheck(detectors=[HeuristicSecretsDetector(), EntropyDetector(), PiiranhaDetector()])

    PII detectors map only credential-like labels to ``secret_detected`` by
    default; pass them an ``*_ALL_LABELS`` mapping to also emit
    ``pii_detected`` (high, review).
    """

    name = "secrets"
    default_code: ClassVar[str] = "secret_detected"
    specs: ClassVar[dict[str, FindingSpec]] = {
        "secret_detected": FindingSpec(
            severity=Severity.CRITICAL,
            action=Action.DELETE,
            message="Secret-like content detected.",
        ),
        "pii_detected": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message="Personal data detected; confirm it may be remembered.",
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        return [HeuristicSecretsDetector()]


__all__ = ["SecretsCheck"]
