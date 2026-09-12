"""Detect and redact secrets in candidate content.

Findings never contain the raw secret — only the *kinds* detected and a
redacted rewrite. When redaction is enabled (default) the recommended action
is ``rewrite`` (persist the redacted content); otherwise the write is blocked.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, Severity
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from ..redaction import redact_text
from .base import BaseCheck


class SecretsCheck(BaseCheck):
    """Flag credentials/keys/tokens and provide a redacted rewrite."""

    name = "secrets"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        redacted, kinds = redact_text(candidate.content)
        if not kinds:
            return []

        if context.config.redact_secrets:
            severity = Severity.HIGH
            action = Action.REWRITE
            message = "Secret-like content detected; will be redacted before persistence."
            evidence: dict[str, object] = {"kinds": kinds, "rewritten_content": redacted}
        else:
            severity = Severity.CRITICAL
            action = Action.BLOCK
            message = "Secret-like content detected; blocked (redaction disabled)."
            evidence = {"kinds": kinds}

        return [
            Finding(
                code="secret_detected",
                category=Category.SECURITY,
                severity=severity,
                message=message,
                evidence=evidence,
                check=self.name,
                recommended_action=action,
            )
        ]


__all__ = ["SecretsCheck"]
