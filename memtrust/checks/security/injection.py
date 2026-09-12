"""Detect attempts to persist agent-directed instructions / prompt injection.

Pattern matching is treated as **one signal**, not proof. Novel phrasings,
obfuscation, and non-English text will be missed.
"""

from __future__ import annotations

import re

from ...context import CheckContext
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ..base import BaseCheck

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bignore (all |the |your )?(previous|prior|above|earlier) "
        r"(instructions|rules|messages|context)\b",
        r"\bdisregard (all |the |your )?(previous|prior|above) (instructions|rules)\b",
        r"\bremember (this )?(permanently|forever|always)\b",
        r"\balways remember\b",
        r"\bnever forget\b",
        r"\boverride (the )?(policy|rules|system|instructions)\b",
        r"\bbypass (the )?(approval|policy|rules|checks|restrictions)\b",
        r"\b(never|do not|don't) tell (the )?(user|customer|human)\b",
        r"\balways execute\b",
        r"\byou are now\b",
        r"\bnew instructions\b",
        r"\bsystem prompt\b",
        r"\bignore your (guidelines|guardrails|safety)\b",
    ]
]


class InjectionCheck(BaseCheck):
    """Flag persistent-instruction / injection phrases in candidate content."""

    name = "injection"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        matched: list[str] = []
        for pattern in _INJECTION_PATTERNS:
            m = pattern.search(candidate.content)
            if m:
                matched.append(m.group(0).strip().lower())
        if not matched:
            return []
        return [
            Finding(
                code="persistent_instruction",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                message="Content contains agent-directed instruction/injection phrases.",
                evidence={"matches": sorted(set(matched))},
                check=self.name,
                recommended_action=Action.REVIEW,
            )
        ]


__all__ = ["InjectionCheck"]
