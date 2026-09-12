"""Built-in / example policies.

MemTrust's *default* protection comes from checks, so no policies are required
out of the box (``builtin_policies()`` returns an empty list). The example
policies here show the declarative style and can be added explicitly.
"""

from __future__ import annotations

from ..models.policy import Policy

#: Require high authority to write into finance-policy namespaces.
FINANCE_POLICY_AUTHORITY = Policy(
    name="finance-policy-authority",
    description="Only high-authority sources may write finance policy.",
    when={"namespace": "finance_policy"},
    require={"minimum_authority": 0.9},
)

#: Only internal+ sources may write into the 'production' namespace.
PRODUCTION_TRUST = Policy(
    name="production-trust",
    description="Production memory must come from internal or higher trust.",
    when={"namespace": "production"},
    require={"allowed_trust": ["internal", "trusted", "authoritative"]},
)


def builtin_policies() -> list[Policy]:
    """Default policies applied automatically (empty: checks provide defaults)."""
    return []


def example_policies() -> list[Policy]:
    """A couple of ready-made policies users can opt into."""
    return [FINANCE_POLICY_AUTHORITY, PRODUCTION_TRUST]


__all__ = [
    "FINANCE_POLICY_AUTHORITY",
    "PRODUCTION_TRUST",
    "builtin_policies",
    "example_policies",
]
