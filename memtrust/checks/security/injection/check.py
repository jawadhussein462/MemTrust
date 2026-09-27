"""The injection check: persistent instructions / prompt injection in memory content."""

from __future__ import annotations

from typing import ClassVar

from ....models.enums import Action, Severity
from ..base import Detector, FindingSpec, SecurityCheck
from .heuristic import HeuristicInjectionDetector


class InjectionCheck(SecurityCheck):
    """Flag agent-directed instructions that should never be persisted.

    Defaults to the offline heuristic detector. Stack model or hosted
    detectors for recall on paraphrases and other languages::

        InjectionCheck(detectors=[HeuristicInjectionDetector(), PromptGuardDetector()])
    """

    name = "injection"
    default_code: ClassVar[str] = "persistent_instruction"
    specs: ClassVar[dict[str, FindingSpec]] = {
        "persistent_instruction": FindingSpec(
            severity=Severity.HIGH,
            action=Action.REVIEW,
            message="Content contains agent-directed instruction/injection phrases.",
        ),
    }

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        return [HeuristicInjectionDetector()]


__all__ = ["InjectionCheck"]
