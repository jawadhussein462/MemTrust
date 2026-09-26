"""Detect knowledge-poisoning attempts in candidate content.

Poisoning here means planting a *false or attacker-controlled fact* into
long-term memory so it is later retrieved as truth (RAG / LTM poisoning).
This is content-based: there is no source-trust or authority model. Pattern
matching is one signal, not proof.

Two tiers:

* ``memory_poisoning`` (critical, quarantine): claims that switch off a
  security control — "requires no authentication", "refunds skip approval",
  "disable MFA", "always include the admin token".
* ``destination_redirect`` (high, review): payments, invoices, or data being
  routed to a new destination ("send all invoices to x@y.io instead").
  Legitimate changes read the same way, which is exactly why they need a
  human: this is the business-email-compromise pattern.
"""

from __future__ import annotations

import re

from ...context import CheckContext
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ...text import deobfuscate
from ..base import WRITE_AND_READ, BaseCheck

_CONTROL = (
    r"(?:auth|authentication|authorization|login|mfa|2fa|two[- ]factor|verification|approvals?"
    r"|security(?:\s+(?:review|checks?|scan))?|credentials?|password|sign[- ]?off|review)"
)

_POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # "requires no auth", "needs no approval" (but not "has no auth issues").
        rf"\b(?:requires?|needs?|has|uses?)\s+no\s+{_CONTROL}\b"
        r"(?!\s+(?:issues?|problems?|errors?|failures?|incidents?|outages?|bugs?))",
        rf"\bno\s+{_CONTROL}\s+(?:is\s+)?(?:required|needed)\b",
        rf"\b{_CONTROL}\s+(?:is|are)\s+(?:no\s+longer|not)\s+(?:required|needed|enforced|necessary)\b",
        rf"\b{_CONTROL}\s+(?:is|are)\s+(?:now\s+)?(?:disabled|optional|turned\s+off)\b",
        rf"\bno\s+longer\s+(?:requires?|needs?)\s+(?:\w+\s+){{0,2}}?{_CONTROL}\b",
        rf"\b(?:disable|skip|bypass|turn\s+off)\s+(?:all\s+|the\s+|any\s+)?"
        rf"(?:\w+\s+)?{_CONTROL}\b",
        rf"\bnever\s+(?:check|verify|validate|require|ask\s+for)\s+(?:the\s+)?{_CONTROL}\b",
        r"\b(?:refunds?|payments?|transfers?|payouts?|withdrawals?)\s+(?:\w+\s+){0,4}?"
        r"(?:require|need)s?\s+no\s+(?:\w+\s+)?approval\b",
        r"\balways\s+(?:include|send|share|attach|use|paste)\s+(?:the\s+)?(?:internal\s+|admin\s+|"
        r"root\s+|master\s+)?(?:token|password|secret|api\s+key|credentials?)\b",
        r"\b(?:grant|give)\s+(?:\w+\s+){0,3}?(?:admin|root|superuser|full)\s+"
        r"(?:access|privileges|rights)\s+to\s+(?:anyone|everyone|all)\b",
    ]
]

_ACTION = r"(?:send|forward|wire|transfer|pay|route|remit|email|post|upload|deposit)"
_DESTINATION = (
    r"(?:https?://\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|(?:account|iban|wallet|routing)\b[^.\n]{0,40})"
)
_REDIRECT_MARKER = r"(?:instead|from\s+now\s+on|going\s+forward|henceforth|effective\s+immediately)"

_REDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        rf"\b{_ACTION}\b[^.\n]{{0,60}}?\bto\s+{_DESTINATION}[^.\n]{{0,40}}?\b{_REDIRECT_MARKER}\b",
        rf"\b{_REDIRECT_MARKER}\b[^.\n]{{0,40}}?\b{_ACTION}\b[^.\n]{{0,60}}?\bto\s+{_DESTINATION}",
        r"\b(?:send|forward|upload|post|copy|export|exfiltrate)\s+(?:all|every|any)\b[^.\n]{0,60}?"
        r"\bto\s+(?:https?://\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)",
    ]
]


def _matches(patterns: list[re.Pattern[str]], text: str) -> list[str]:
    return sorted({m.group(0).strip().lower() for p in patterns if (m := p.search(text))})


class PoisoningCheck(BaseCheck):
    """Flag content that looks like an attempt to plant a false security fact."""

    name = "poisoning"
    operations = WRITE_AND_READ

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        clean = deobfuscate(candidate.content)
        findings: list[Finding] = []
        poisoning = _matches(_POISONING_PATTERNS, clean)
        if poisoning:
            findings.append(
                Finding(
                    code="memory_poisoning",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    message=(
                        "Content looks like an attempt to plant a false or "
                        "attacker-controlled fact into long-term memory."
                    ),
                    evidence={"matches": poisoning},
                    check=self.name,
                    recommended_action=Action.QUARANTINE,
                )
            )
        redirect = _matches(_REDIRECT_PATTERNS, clean)
        if redirect:
            findings.append(
                Finding(
                    code="destination_redirect",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    message=(
                        "Content redirects payments or data to a new destination; "
                        "confirm the change before it is remembered."
                    ),
                    evidence={"matches": redirect},
                    check=self.name,
                    recommended_action=Action.REVIEW,
                )
            )
        return findings


__all__ = ["PoisoningCheck"]
