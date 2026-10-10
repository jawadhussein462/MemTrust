"""The poisoning check: false or attacker-controlled facts planted in memory."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ....owasp import ASI06_REF
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicPoisoningDetector
from .hubness import HubnessDetector
from .trustrag import TrustRAGDetector


class PoisoningCheck(SecurityCheck):
    """Flag content that looks like an attempt to plant a false fact.

    Defaults are offline: the phrase list, TrustRAG (needs the other
    records in the batch), and hubness (needs stored embeddings). Model
    methods — RAGuard, NLI, probe-query, embedding consistency — are
    optional detectors you add yourself.

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
            severity=Severity.HIGH,
            action=Action.QUARANTINE,
            message=(
                "Content matches a control-bypass phrase; a regex hit is a "
                "signal, not proof of a planted fact. Review before treating "
                "it as poison."
            ),
            owasp=ASI06_REF,
        ),
        "destination_redirect": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Content redirects payments or data to a new destination; "
                "confirm the change before it is remembered."
            ),
            owasp=ASI06_REF,
        ),
        "poisoning_cluster": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Content is one of several near-identical retrieved records, the "
                "multi-document poisoning pattern; confirm they are legitimate copies."
            ),
            owasp=ASI06_REF,
        ),
        "adversarial_text": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "A span of this content reads as machine-optimised rather than "
                "natural text (chunk-wise language-model perplexity)."
            ),
            owasp=ASI06_REF,
        ),
        "hub_record": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "This record appears in unusually many other records' nearest "
                "neighbours, the hubness pattern of a passage written to be "
                "retrieved for many queries."
            ),
            owasp=ASI06_REF,
        ),
        "embedding_mismatch": FindingSpec(
            severity=Severity.HIGH,
            action=Action.QUARANTINE,
            message=(
                "The stored vector does not match a fresh embedding of the "
                "text; the vector may have been written directly or tampered with."
            ),
            owasp=ASI06_REF,
        ),
        "temporal_contradiction": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "A newer record contradicts older established neighbours; "
                "confirm the update is legitimate."
            ),
            owasp=ASI06_REF,
        ),
        "retrieval_flip": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "Removing this record changes the answer to probe questions "
                "generated from it; it may be the sole source of a planted fact."
            ),
            owasp=ASI06_REF,
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        """Return the offline corpus detectors.

        Returns:
            Phrase list, TrustRAG, and hubness. Hubness no-ops when the
            batch has no embeddings. TrustRAG uses stored vectors when
            present and lexical similarity on small batches otherwise.
        """
        return [HeuristicPoisoningDetector(), TrustRAGDetector(), HubnessDetector()]


__all__ = ["PoisoningCheck"]
