"""Detect secrets in candidate content.

Findings never contain the raw secret — only the *kinds* detected.
Secret-bearing writes are blocked.
"""

from __future__ import annotations

import re

from ...context import CheckContext
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ..base import WRITE_AND_READ, BaseCheck

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"),
    ),
    ("private_key", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{10,}=*")),
]

_CREDENTIAL = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b"
    r"(\s*[:=]\s*)"
    r"([^\s\"']{6,})"
)


def _secret_kinds(text: str) -> list[str]:
    kinds: set[str] = set()
    for kind, pattern in _PATTERNS:
        if pattern.search(text):
            kinds.add(kind)
    if _CREDENTIAL.search(text):
        kinds.add("credential")
    return sorted(kinds)


class SecretsCheck(BaseCheck):
    """Flag credentials/keys/tokens and block the write."""

    name = "secrets"
    operations = WRITE_AND_READ

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        kinds = _secret_kinds(candidate.content)
        if not kinds:
            return []

        return [
            Finding(
                code="secret_detected",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                message="Secret-like content detected.",
                evidence={"kinds": kinds},
                check=self.name,
                recommended_action=Action.BLOCK,
            )
        ]


__all__ = ["SecretsCheck"]
