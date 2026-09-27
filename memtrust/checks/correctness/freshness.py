"""Write-time freshness checks.

Read-time expiry filtering is enforced in the core engine so expired or
not-yet-valid memories never reach an agent. This check warns at write time
when a candidate is already expired or its validity window is inverted.
"""

from __future__ import annotations

from ...context import CheckContext
from ...models.enums import Action, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from .base import CorrectnessCheck


class FreshnessCheck(CorrectnessCheck):
    """Flag candidates that are already stale or have an invalid time window."""

    name = "freshness"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        now = context.now
        findings: list[Finding] = []

        if candidate.expires_at is not None and candidate.expires_at <= now:
            findings.append(
                self.finding(
                    "expired_on_write",
                    severity=Severity.MEDIUM,
                    action=Action.ALLOW_WITH_WARNING,
                    message="Candidate is already expired at write time.",
                    evidence={
                        "expires_at": candidate.expires_at.isoformat(),
                        "now": now.isoformat(),
                    },
                )
            )

        if (
            candidate.valid_from is not None
            and candidate.valid_until is not None
            and candidate.valid_from > candidate.valid_until
        ):
            findings.append(
                self.finding(
                    "invalid_validity_window",
                    severity=Severity.MEDIUM,
                    action=Action.ALLOW_WITH_WARNING,
                    message="valid_from is after valid_until.",
                    evidence={
                        "valid_from": candidate.valid_from.isoformat(),
                        "valid_until": candidate.valid_until.isoformat(),
                    },
                )
            )
        return findings


__all__ = ["FreshnessCheck"]
