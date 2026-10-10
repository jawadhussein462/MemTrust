"""Phrase patterns for false security facts and destination redirects.

Poisoning here means planting a false or attacker-controlled fact so it is
later retrieved as truth. There is no source-trust model. A regex hit is
one signal, not proof.

Two finding codes:

* `memory_poisoning` (critical, quarantine): a claim that turns off a
  control. Examples: "requires no authentication", "refunds skip approval",
  "disable MFA", "always include the admin token".
* `destination_redirect` (high, review): payments, invoices, or data sent
  somewhere new, such as "send all invoices to x@y.io instead". A real
  change reads the same way, which is why a person should confirm it.
"""

from __future__ import annotations

import re

from ....text import deobfuscate
from ..base import BaseDetector, Detection

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


def poisoning_matches(text: str) -> list[str]:
    """List phrases that claim a security control is off.

    Args:
        text: Memory content. It is deobfuscated before matching.

    Returns:
        The matched phrases, lowercased, duplicates removed, sorted.
        Empty when nothing matched.
    """
    return _matches(_POISONING_PATTERNS, deobfuscate(text))


def redirect_matches(text: str) -> list[str]:
    """List phrases that send payments or data to a new destination.

    Args:
        text: Memory content. It is deobfuscated before matching.

    Returns:
        The matched phrases, lowercased, duplicates removed, sorted.
        Empty when nothing matched.
    """
    return _matches(_REDIRECT_PATTERNS, deobfuscate(text))


class HeuristicPoisoningDetector(BaseDetector):
    """Match control-bypass and payment-redirect phrases. Offline.

    One memory can produce both a `memory_poisoning` hit and a
    `destination_redirect` hit.
    """

    name = "heuristic"

    def detect_text(self, text: str) -> list[Detection]:
        clean = deobfuscate(text)
        detections: list[Detection] = []
        poisoning = _matches(_POISONING_PATTERNS, clean)
        if poisoning:
            detections.append(self.hit(code="memory_poisoning", matches=poisoning))
        redirect = _matches(_REDIRECT_PATTERNS, clean)
        if redirect:
            detections.append(self.hit(code="destination_redirect", matches=redirect))
        return detections


__all__ = ["HeuristicPoisoningDetector", "poisoning_matches", "redirect_matches"]
