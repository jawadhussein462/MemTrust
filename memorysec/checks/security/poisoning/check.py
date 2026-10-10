"""The poisoning check: false or attacker-controlled facts planted in memory."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicPoisoningDetector


class PoisoningCheck(SecurityCheck):
    """Flag content that looks like an attempt to plant a false fact.

    The default detector is the offline phrase list. TrustRAG also needs
    the other records from a batched scan (`context.existing`).

    Example:
        Run the phrase list and the cluster detector together::

            PoisoningCheck(detectors=[
                HeuristicPoisoningDetector(),
                TrustRAGDetector(),
            ])
    """

    name = "poisoning"
    default_code: ClassVar[str] = "memory_poisoning"
    specs: ClassVar[dict[str, FindingSpec]] = {
        "memory_poisoning": FindingSpec(
            severity=Severity.CRITICAL,
            action=Action.QUARANTINE,
            message=(
                "Content looks like an attempt to plant a false or "
                "attacker-controlled fact into long-term memory."
            ),
        ),
        "destination_redirect": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Content redirects payments or data to a new destination; "
                "confirm the change before it is remembered."
            ),
        ),
        "poisoning_cluster": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Content is one of several near-identical retrieved records, the "
                "multi-document poisoning pattern; confirm they are legitimate copies."
            ),
        ),
        "adversarial_text": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Content reads as machine-optimised rather than natural text "
                "(very high language-model perplexity)."
            ),
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        """Return the offline phrase detector.

        Returns:
            A one-item list: `HeuristicPoisoningDetector`.
        """
        return [HeuristicPoisoningDetector()]


__all__ = ["PoisoningCheck"]
