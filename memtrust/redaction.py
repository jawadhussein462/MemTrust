"""Secret detection and redaction.

Used both by :class:`~memtrust.checks.secrets.SecretsCheck` and by the audit
layer, so that raw secrets never reach findings, audit events, logs, or
telemetry — even if the secrets check itself is disabled.

These are heuristic patterns. They catch common, high-signal credential
formats; they are **not** a complete secret scanner. See ``SECURITY.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_REDACT = "[REDACTED:{kind}]"

# High-signal, low-false-positive patterns, applied in this order.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----")),
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

# Credential assignments like ``password: hunter2`` — keep the key, redact value.
_CREDENTIAL = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b"
    r"(\s*[:=]\s*)"
    r"([^\s\"']{6,})"
)


@dataclass(frozen=True)
class SecretMatch:
    """A detected secret: its kind and character span (never its value)."""

    kind: str
    start: int
    end: int


def find_secrets(text: str) -> list[SecretMatch]:
    """Return spans of detected secrets, without exposing their values."""
    matches: list[SecretMatch] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            matches.append(SecretMatch(kind=kind, start=m.start(), end=m.end()))
    for m in _CREDENTIAL.finditer(text):
        matches.append(SecretMatch(kind="credential", start=m.start(3), end=m.end(3)))
    return matches


def redact_text(text: str) -> tuple[str, list[str]]:
    """Return ``(redacted_text, kinds_found)``.

    ``kinds_found`` is a sorted, de-duplicated list of the secret kinds that
    were redacted; it is safe to include in findings and audit events.
    """
    kinds: set[str] = set()
    redacted = text
    for kind, pattern in _PATTERNS:
        redacted, n = pattern.subn(_REDACT.format(kind=kind), redacted)
        if n:
            kinds.add(kind)

    def _cred(m: re.Match[str]) -> str:
        kinds.add("credential")
        return f"{m.group(1)}{m.group(2)}{_REDACT.format(kind='credential')}"

    redacted = _CREDENTIAL.sub(_cred, redacted)
    return redacted, sorted(kinds)


def has_secrets(text: str) -> bool:
    _, kinds = redact_text(text)
    return bool(kinds)


__all__ = ["SecretMatch", "find_secrets", "has_secrets", "redact_text"]
