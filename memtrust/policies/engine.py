"""Policy evaluation.

Evaluates declarative :class:`~memtrust.Policy` objects and plain callables
against a candidate, returning the names of matched policies and any findings
they produced.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category, TrustLevel
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from ..models.policy import Policy
from .base import PolicyCallable


class PolicyEngine:
    """Holds and evaluates policies (declarative + callable)."""

    def __init__(
        self,
        policies: list[Policy] | None = None,
        callables: list[PolicyCallable] | None = None,
    ) -> None:
        self.policies = list(policies or [])
        self.callables = list(callables or [])

    def evaluate(
        self, candidate: MemoryCandidate, context: CheckContext
    ) -> tuple[list[str], list[Finding]]:
        matched: list[str] = []
        findings: list[Finding] = []

        for policy in self.policies:
            if not self._matches(policy, candidate, context):
                continue
            matched.append(policy.name)
            findings.extend(self._apply_requirements(policy, candidate))

        for fn in self.callables:
            result = fn(candidate, context)
            produced = _as_list(result)
            if produced:
                matched.append(getattr(fn, "__name__", fn.__class__.__name__))
                findings.extend(produced)

        return matched, findings

    # -- matching ---------------------------------------------------------------

    def _matches(self, policy: Policy, candidate: MemoryCandidate, context: CheckContext) -> bool:
        when = policy.when
        scope = candidate.scope
        source = candidate.source

        if "tenant_id" in when and scope.tenant_id != when["tenant_id"]:
            return False
        if "namespace" in when and scope.namespace != when["namespace"]:
            return False
        if "namespace_in" in when:
            allowed = when["namespace_in"]
            if not isinstance(allowed, (list, tuple, set)) or scope.namespace not in allowed:
                return False
        if "source_type" in when and source.type != when["source_type"]:
            return False
        if "source_trust_at_most" in when:
            limit = TrustLevel(str(when["source_trust_at_most"]))
            if source.trust.rank > limit.rank:
                return False
        return True

    # -- requirements -----------------------------------------------------------

    def _apply_requirements(self, policy: Policy, candidate: MemoryCandidate) -> list[Finding]:
        require = policy.require
        findings: list[Finding] = []
        action = policy.action or Action.BLOCK

        if "minimum_authority" in require:
            minimum = float(require["minimum_authority"])  # type: ignore[arg-type]
            if candidate.effective_authority < minimum:
                findings.append(
                    Finding(
                        code="policy_authority_violation",
                        category=Category.GOVERNANCE,
                        severity=policy.severity,
                        message=(
                            f"Policy '{policy.name}' requires authority >= {minimum:.2f}, "
                            f"but candidate authority is {candidate.effective_authority:.2f}."
                        ),
                        evidence={
                            "policy": policy.name,
                            "minimum_authority": minimum,
                            "actual_authority": candidate.effective_authority,
                        },
                        check=f"policy:{policy.name}",
                        recommended_action=action,
                    )
                )

        if "allowed_trust" in require:
            allowed = {str(t) for t in require["allowed_trust"]}  # type: ignore[union-attr]
            if candidate.source.trust.value not in allowed:
                findings.append(
                    Finding(
                        code="policy_trust_violation",
                        category=Category.GOVERNANCE,
                        severity=policy.severity,
                        message=(
                            f"Policy '{policy.name}' allows only trust {sorted(allowed)}, "
                            f"but source trust is '{candidate.source.trust.value}'."
                        ),
                        evidence={"policy": policy.name, "allowed_trust": sorted(allowed)},
                        check=f"policy:{policy.name}",
                        recommended_action=action,
                    )
                )
        return findings


def _as_list(result: Finding | list[Finding] | None) -> list[Finding]:
    if result is None:
        return []
    if isinstance(result, Finding):
        return [result]
    return list(result)


__all__ = ["PolicyEngine"]
