"""Write-side tenant hygiene.

Hard cross-tenant enforcement (write *and* read) lives in the core engine so
it cannot be removed by customizing the check list. This pluggable check only
adds the "no explicit tenant set" governance warning.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, Severity
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from .base import BaseCheck


class TenantCheck(BaseCheck):
    """Warn when a write has no explicit tenant (uses the 'default' sentinel)."""

    name = "tenant"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        if context.config.require_tenant and candidate.scope.tenant_id == "default":
            return [
                Finding(
                    code="missing_tenant",
                    category=Category.GOVERNANCE,
                    severity=Severity.LOW,
                    message="No explicit tenant set; using 'default'. Set scope.tenant_id in production.",
                    evidence={},
                    check=self.name,
                    recommended_action=Action.ALLOW_WITH_WARNING,
                )
            ]
        return []


__all__ = ["TenantCheck"]
