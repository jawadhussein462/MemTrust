"""Detect unauthorized scope expansion (promotion).

The classic case: information from a single user (``user=alice``) is written
as tenant-wide memory (``tenant=acme`` with no ``user_id``) without an
explicit policy allowing the promotion. Left unchecked, one user's statements
silently become facts for the whole tenant.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, Severity, TrustLevel
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from .base import BaseCheck


class ScopeCheck(BaseCheck):
    """Flag user/untrusted-sourced writes that broaden to tenant scope."""

    name = "scope"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        source_trust = candidate.source.trust
        scope = candidate.scope

        # Only user/untrusted material is at risk of illegitimate promotion.
        if source_trust.rank > TrustLevel.USER.rank:
            return []
        # If it is attributed to a user, it isn't being promoted tenant-wide.
        if scope.user_id is not None:
            return []
        # Policy-namespace authority is handled by AuthorityCheck; avoid double flags.
        if context.config.is_policy_namespace(scope.namespace):
            return []

        return [
            Finding(
                code="scope_promotion",
                category=Category.GOVERNANCE,
                severity=Severity.MEDIUM,
                message=(
                    f"'{source_trust.value}'-sourced content is being written at tenant scope "
                    "without user attribution (possible unauthorized promotion)."
                ),
                evidence={
                    "source_trust": source_trust.value,
                    "tenant_id": scope.tenant_id,
                    "namespace": scope.namespace,
                },
                check=self.name,
                # A governance heads-up, not a hard block: surfaced as a warning so
                # legitimate tenant-level writes are not blocked by default. Tighten
                # with a policy when promotion must require explicit approval.
                recommended_action=Action.ALLOW_WITH_WARNING,
            )
        ]


__all__ = ["ScopeCheck"]
