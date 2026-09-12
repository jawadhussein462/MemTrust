"""Authority checks: authority is distinct from confidence.

An extractor may be highly *confident* it read a rule from a customer email,
but the customer has no *authority* to define company policy. This check
compares a candidate's authority (explicit, or implied by source trust)
against the authority required by its target namespace and content.
"""

from __future__ import annotations

import re

from ..context import CheckContext
from ..models.enums import Action, Category, Severity, TrustLevel
from ..models.finding import Finding
from ..models.memory import MemoryCandidate
from .base import BaseCheck

# Phrases that assert a rule / permission / policy change.
_POLICY_ASSERTION = re.compile(
    r"(?i)\b("
    r"bypass\s+(the\s+)?(manager\s+)?approval"
    r"|(no|without|not)\s+(manager\s+)?(approval|authorization|sign-?off)"
    r"|(require|requires|need|needs)\s+no\s+(approval|authorization)"
    r"|no\s+longer\s+(require|requires|need|needs)"
    r"|approval\s+is\s+(no\s+longer\s+)?(not\s+)?(required|needed)"
    r"|(is|are)\s+(now\s+)?(allowed|permitted|authorized|prohibited|forbidden)"
    r"|policy\s+is"
    r"|refunds?\s+under"
    r")\b"
)


class AuthorityCheck(BaseCheck):
    """Flag low-authority attempts to write rules/policy."""

    name = "authority"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        config = context.config
        namespace = candidate.scope.namespace
        required = config.required_authority(namespace)
        actual = candidate.effective_authority
        is_policy_ns = config.is_policy_namespace(namespace)
        asserts_policy = _POLICY_ASSERTION.search(candidate.content) is not None
        low_trust = candidate.source.trust.rank <= TrustLevel.USER.rank
        policy_threshold = config.policy_namespace_threshold

        # Untrusted/user source trying to assert policy (by namespace or content).
        if (is_policy_ns or asserts_policy) and low_trust and actual < policy_threshold:
            return [
                Finding(
                    code="untrusted_policy_write",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    message=(
                        "Untrusted/low-authority content is attempting to create persistent "
                        "policy memory."
                    ),
                    evidence={
                        "namespace": namespace,
                        "required_authority": max(required, policy_threshold),
                        "actual_authority": actual,
                        "source_trust": candidate.source.trust.value,
                        "asserts_policy": asserts_policy,
                    },
                    check=self.name,
                    recommended_action=Action.QUARANTINE,
                )
            ]

        # Generic insufficient authority for a protected namespace.
        if required > 0 and actual < required:
            return [
                Finding(
                    code="insufficient_authority",
                    category=Category.GOVERNANCE,
                    severity=Severity.HIGH,
                    message=(
                        f"Authority {actual:.2f} is below the {required:.2f} required to write "
                        f"into namespace '{namespace}'."
                    ),
                    evidence={
                        "namespace": namespace,
                        "required_authority": required,
                        "actual_authority": actual,
                    },
                    check=self.name,
                    recommended_action=Action.REVIEW,
                )
            ]
        return []


__all__ = ["AuthorityCheck"]
