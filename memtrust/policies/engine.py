"""Policy evaluation.

Evaluates declarative :class:`~memtrust.Policy` objects and plain callables
against a candidate, returning the names of matched policies and any findings
they produced.
"""

from __future__ import annotations

from ..context import CheckContext
from ..models.enums import Action, Category
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
            if not self._matches(policy, candidate):
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

    def _matches(self, policy: Policy, candidate: MemoryCandidate) -> bool:
        when = policy.when
        return all(candidate.metadata.get(key) == expected for key, expected in when.items())

    def _apply_requirements(self, policy: Policy, candidate: MemoryCandidate) -> list[Finding]:
        require = policy.require
        findings: list[Finding] = []
        action = policy.action or Action.BLOCK
        content = candidate.content.lower()

        if "forbidden_substrings" in require:
            terms = require["forbidden_substrings"]
            if not isinstance(terms, (list, tuple, set)):
                terms = [terms]
            hits = [str(t) for t in terms if str(t).lower() in content]
            if hits:
                findings.append(
                    Finding(
                        code="policy_content_violation",
                        category=Category.SECURITY,
                        severity=policy.severity,
                        message=(
                            f"Policy '{policy.name}' forbids content containing "
                            f"{sorted(h.lower() for h in hits)}."
                        ),
                        evidence={"policy": policy.name, "matches": hits},
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
