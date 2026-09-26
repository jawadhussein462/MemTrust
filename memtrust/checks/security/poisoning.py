"""Detect knowledge-poisoning attempts in candidate content.

Poisoning here means planting a *false or attacker-controlled fact* into
long-term memory so it is later retrieved as truth (RAG / LTM poisoning).
This is content-based: there is no source-trust or authority model. Pattern
matching is one signal, not proof.
"""

from __future__ import annotations

import re

from ...context import CheckContext
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ..base import WRITE_AND_READ, BaseCheck

_POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(requires?|needs?|has) no auth",
        r"\bno authentication\b",
        r"\bdisable (all )?(auth|security|verification|guardrails)\b",
        r"\b(skip|bypass) (all )?(auth|authentication|verification|approval|security)\b",
        r"\battacker\.(example|com|net|org)\b",
        r"\brefunds? (require|need) no approval\b",
        r"\brefunds? no longer require\b",
        r"\balways (include|send|use) (the )?(internal |admin )?(token|password|secret|key)\b",
        r"\bofficial (api )?host is\b",
        r"\bhost is attacker\b",
        r"\bnever (check|verify|validate|require) (auth|approval|credentials)\b",
        r"\bproduction api (host|requires|needs)\b",
    ]
]


class PoisoningCheck(BaseCheck):
    """Flag content that looks like an attempt to plant a false security fact."""

    name = "poisoning"
    operations = WRITE_AND_READ

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        matched: list[str] = []
        for pattern in _POISONING_PATTERNS:
            m = pattern.search(candidate.content)
            if m:
                matched.append(m.group(0).strip().lower())
        if not matched:
            return []
        return [
            Finding(
                code="memory_poisoning",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                message=(
                    "Content looks like an attempt to plant a false or "
                    "attacker-controlled fact into long-term memory."
                ),
                evidence={"matches": sorted(set(matched))},
                check=self.name,
                recommended_action=Action.QUARANTINE,
            )
        ]


__all__ = ["PoisoningCheck"]
