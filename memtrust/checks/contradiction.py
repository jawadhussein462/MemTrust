"""Contradiction and supersession, via the pluggable semantic analyzer.

Correctness is not reduced to similarity. Using time and authority, a newer
fact from an equally- or more-authoritative source *supersedes* an old one
(history preserved), whereas a genuine conflict is flagged for review. A
lower-authority source can never silently replace a higher-authority memory
(security Invariant 2).
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, MemoryRelationship, MemoryStatus, Severity
from ..models.finding import Finding
from ..models.memory import MemoryCandidate, MemoryRecord
from .base import BaseCheck


def _comparable(candidate: MemoryCandidate, existing: MemoryRecord) -> bool:
    return (
        existing.scope.tenant_id == candidate.scope.tenant_id
        and existing.scope.user_id == candidate.scope.user_id
        and existing.status == MemoryStatus.ACTIVE
    )


class ContradictionCheck(BaseCheck):
    """Classify candidate-vs-existing relationships and act accordingly."""

    name = "contradiction"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        if not context.config.contradiction_enabled:
            return []

        findings: list[Finding] = []
        for existing in context.existing:
            if not _comparable(candidate, existing):
                continue
            rel = context.semantic.compare(existing, candidate)
            downgrade = candidate.effective_authority < existing.authority

            if rel == MemoryRelationship.SUPERSEDES:
                if downgrade:
                    findings.append(self._authority_downgrade(candidate, existing, rel))
                else:
                    findings.append(
                        Finding(
                            code="supersedes_existing",
                            category=Category.CORRECTNESS,
                            severity=Severity.LOW,
                            message=f"Candidate is a newer version of memory '{existing.id}'.",
                            evidence={"supersedes": [existing.id]},
                            check=self.name,
                            recommended_action=Action.SUPERSEDE,
                        )
                    )
            elif rel == MemoryRelationship.CONTRADICTS:
                if downgrade:
                    findings.append(self._authority_downgrade(candidate, existing, rel))
                else:
                    findings.append(
                        Finding(
                            code="contradiction",
                            category=Category.CORRECTNESS,
                            severity=Severity.MEDIUM,
                            message=f"Candidate conflicts with existing memory '{existing.id}'.",
                            evidence={"conflicts_with": existing.id},
                            check=self.name,
                            recommended_action=Action.REVIEW,
                        )
                    )
        return findings

    def _authority_downgrade(
        self, candidate: MemoryCandidate, existing: MemoryRecord, rel: MemoryRelationship
    ) -> Finding:
        return Finding(
            code="authority_downgrade",
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            message=(
                f"Lower-authority content ({candidate.effective_authority:.2f}) may not "
                f"{rel.value} higher-authority memory '{existing.id}' "
                f"({existing.authority:.2f})."
            ),
            evidence={
                "existing_id": existing.id,
                "existing_authority": existing.authority,
                "candidate_authority": candidate.effective_authority,
                "relationship": rel.value,
            },
            check=self.name,
            recommended_action=Action.REVIEW,
        )


__all__ = ["ContradictionCheck"]
