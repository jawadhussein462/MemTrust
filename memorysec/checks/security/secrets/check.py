"""The secrets check: credentials, keys, tokens, and, if you opt in, personal data."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicSecretsDetector


class SecretsCheck(SecurityCheck):
    """Flag secret-bearing content, and optionally personal data for review.

    Findings never contain the raw value. They list the kinds detected.
    The default detector is the offline pattern list. Add entropy or a model
    for formats that list does not know.

    Personal-data detectors map only credential-like labels to
    `secret_detected` by default. Pass them an `*_ALL_LABELS` mapping to also
    emit `pii_detected` (high, review).

    Example:
        Stack the pattern list, entropy, and Piiranha::

            SecretsCheck(detectors=[
                HeuristicSecretsDetector(),
                EntropyDetector(),
                PiiranhaDetector(),
            ])
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
        """Return the offline key-format detector.

        Returns:
            A one-item list: `HeuristicSecretsDetector`.
        """
        return [HeuristicSecretsDetector()]


__all__ = ["SecretsCheck"]
