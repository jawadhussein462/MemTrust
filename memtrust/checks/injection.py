"""Detect attempts to persist agent-directed instructions / prompt injection.

Pattern matching is treated as **one signal**, not proof. The resulting
severity depends heavily on the trust of the source: the same sentence from
an authoritative internal policy is very different from an untrusted website.
"""

from __future__ import annotations

import re

from ..context import CheckContext
from ..models.enums import Action, Category, Severity, TrustLevel
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from .base import BaseCheck

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bignore (all |the |your )?(previous|prior|above|earlier) (instructions|rules|messages)\b",
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

# Injection severity scales down as source trust rises.
_SEVERITY_BY_TRUST: dict[TrustLevel, Severity] = {
    TrustLevel.UNTRUSTED: Severity.HIGH,
    TrustLevel.USER: Severity.HIGH,
    TrustLevel.AGENT: Severity.MEDIUM,
    TrustLevel.INTERNAL: Severity.LOW,
    TrustLevel.TRUSTED: Severity.LOW,
    TrustLevel.AUTHORITATIVE: Severity.INFO,
}


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

        severity = _SEVERITY_BY_TRUST[candidate.source.trust]
        action = Action.REVIEW if severity.is_at_least(Severity.HIGH) else None
        return [
            Finding(
                code="persistent_instruction",
                category=Category.SECURITY,
                severity=severity,
                message=(
                    "Content contains agent-directed instruction/injection phrases; "
                    f"severity scaled to source trust '{candidate.source.trust.value}'."
                ),
                evidence={"matches": sorted(set(matched)), "source_trust": candidate.source.trust.value},
                check=self.name,
                recommended_action=action,
            )
        ]


__all__ = ["InjectionCheck"]
