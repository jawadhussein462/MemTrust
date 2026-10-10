"""The injection check: instructions aimed at the agent, saved as memory."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ....owasp import LLM01_REF
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicInjectionDetector


class InjectionCheck(SecurityCheck):
    """Flag instructions that tell the agent to ignore its rules.

    Phrases like "ignore previous instructions" should not be stored as
    memory. The default detector is the offline phrase list. Chat-prompt
    classifiers (Prompt Guard, DeBERTa, Sentinel, Lakera, Azure) are
    optional baselines. Known-answer / DataSentinel and the embedding
    classifier are the memory-native methods.

    Example:
        Require both the phrase list and Prompt Guard to agree::

            InjectionCheck(
                detectors=[HeuristicInjectionDetector(), PromptGuardDetector()],
                min_detectors=2,
            )
    """

    name = "injection"
    default_code: ClassVar[str] = "persistent_instruction"
    specs: ClassVar[dict[str, FindingSpec]] = {
        "persistent_instruction": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message="Content contains agent-directed instruction/injection phrases.",
            owasp=LLM01_REF,
        ),
        "known_answer": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "The record stops a language model from following a canary "
                "instruction placed next to it (known-answer detection)."
            ),
            owasp=LLM01_REF,
        ),
        "embedding_injection": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message=(
                "The stored embedding is classified as prompt injection by an "
                "embedding-space linear model."
            ),
            owasp=LLM01_REF,
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        """Return the offline phrase detector.

        Returns:
            A one-item list: `HeuristicInjectionDetector`.
        """
        return [HeuristicInjectionDetector()]


__all__ = ["InjectionCheck"]
