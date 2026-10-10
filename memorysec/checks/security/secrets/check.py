"""The secrets check: credentials, keys, tokens, and, if you opt in, personal data."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ....owasp import LLM02_REF
from ..base import Detector, FindingSpec, SecurityCheck
from .gitleaks import GitleaksDetector
from .heuristic import HeuristicSecretsDetector


class SecretsCheck(SecurityCheck):
    """Flag secret-bearing content, and optionally personal data for review.

    Findings never contain the raw value. They list the kinds detected.
    Defaults are the offline pattern list plus a Gitleaks-rule port.
    Live verification (`SecretVerificationDetector`) is off unless you
    pass a `verify` callback.

    Personal-data detectors map only credential-like labels to
    `secret_detected` by default. Pass them an `*_ALL_LABELS` mapping to also
    emit `pii_detected` (high, review). The actions differ: delete and
    rotate a secret; redact or apply retention to PII.

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
            message="Secret-like content detected. Delete the record and rotate the credential.",
            owasp=LLM02_REF,
        ),
        "pii_detected": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Personal data detected; redact it or apply a retention rule. "
                "Do not treat this as a credential to rotate."
            ),
            owasp=LLM02_REF,
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        """Return the offline format detectors.

        Returns:
            Heuristic patterns and the Gitleaks-rule port.
        """
        return [HeuristicSecretsDetector(), GitleaksDetector()]


__all__ = ["SecretsCheck"]
