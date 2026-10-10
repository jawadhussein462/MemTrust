"""Phrase patterns for prompt injection, after deobfuscation.

A regex hit is one signal, not proof. The text is cleaned first: invisible
characters, look-alike letters, accents, and letter-by-letter spelling
(`"i-g-n-o-r-e"`).

The phrases target hijacking, not ordinary preferences. "Always remember
to CC finance" is a normal memory. "Ignore previous instructions" is not.

New wording, encodings, and most non-English text are missed. Pair this
detector with a model when you need those.
"""

from __future__ import annotations

import re

from ....text import deobfuscate
from ..base import BaseDetector, Detection

_EARLIER = r"(?:previous|prior|above|earlier|preceding|original)"
_RULES = r"(?:instructions?|rules|prompts?|directives|guidelines|guardrails|context)"

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Overriding earlier instructions.
        rf"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|the\s+|any\s+|your\s+)*"
        rf"{_EARLIER}\s+{_RULES}\b",
        rf"\b(?:ignore|disregard|forget)\s+(?:all\s+|the\s+)?{_RULES}\s+(?:above|before)\b",
        r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything)\s+(?:you\s+(?:were|have\s+been"
        r"|'ve\s+been)\s+told|(?:said|written)\s+(?:above|before))\b",
        r"\b(?:ignore|override|bypass|disable)\s+(?:your|the|all)\s+"
        r"(?:guidelines|guardrails|safety|restrictions|system\s+(?:prompt|instructions|rules))\b",
        r"\boverride\s+(?:the\s+)?(?:policy|rules|system|instructions)\b",
        # Persona / mode switches.
        r"\byou\s+are\s+now\s+(?:dan\b|jailbroken|unrestricted|free\s+(?:of|from)"
        r"|no\s+longer\s+bound|in\s+(?:developer|god|jailbreak|dan|unrestricted)\s+mode)",
        r"\byou\s+are\s+now\s+an?\s+[\w\s,-]{0,40}?\b(?:no|without)\s+(?:restrictions|rules|limits"
        r"|filters|guidelines)\b",
        r"\b(?:enter|enable|activate)\s+(?:developer|god|jailbreak|dan)\s+mode\b",
        # Injected instruction blocks and system-prompt extraction.
        r"(?:^|[\n.;]\s*)(?:system|assistant)\s*:\s*(?:new\s+)?instructions?\b",
        r"\b(?:here\s+are\s+)?(?:your|the)\s+new\s+instructions\b",
        r"\bnew\s+instructions\s*:",
        r"\b(?:reveal|print|show|repeat|output|leak|display)\s+(?:me\s+)?(?:your|the)\s+"
        r"(?:full\s+|hidden\s+|original\s+)?system\s+prompt\b",
        # Persistence and secrecy directives aimed at the agent.
        r"\bremember\s+(?:this\s+|that\s+)?(?:permanently|forever)\b",
        r"\b(?:never|do\s+not|don't)\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+"
        r"(?:the\s+)?(?:user|customer|human|operator)\b",
        # Common non-English variants of "ignore previous instructions".
        r"\bignora\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b",
        r"\bignorez?\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:precedentes|anterieures)\b",
        r"\bignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen)\s+anweisungen\b",
        r"\bignore\s+(?:todas\s+)?as\s+instrucoes\s+anteriores\b",
        r"\bignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti\b",
    ]
]


def injection_matches(text: str) -> list[str]:
    """List the injection phrases found in `text`.

    Args:
        text: Memory content. It is deobfuscated before matching, so hidden
            characters do not hide a known phrase.

    Returns:
        The matched phrases, lowercased, with duplicates removed, sorted.
        Empty when nothing matched. The full memory is not returned.
    """
    clean = deobfuscate(text)
    matched = {
        m.group(0).strip(" \n.;").lower() for p in _INJECTION_PATTERNS if (m := p.search(clean))
    }
    return sorted(matched)


class HeuristicInjectionDetector(BaseDetector):
    """Match known injection phrases. Offline, deterministic, and fast.

    No model is downloaded and no network call is made. The same text always
    produces the same hit.
    """

    name = "heuristic"

    def detect_text(self, text: str) -> list[Detection]:
        matched = injection_matches(text)
        if not matched:
            return []
        return [self.hit(matches=matched)]


__all__ = ["HeuristicInjectionDetector", "injection_matches"]
