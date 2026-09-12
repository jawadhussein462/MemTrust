"""Built-in / example policies.

MemTrust's *default* protection comes from checks, so no policies are required
out of the box (``builtin_policies()`` returns an empty list). The example
policies here show the declarative style and can be added explicitly.
"""

from __future__ import annotations

from ..models.policy import Policy

#: Do not persist Social Security numbers.
NO_SSN = Policy(
    name="no-ssn",
    description="Do not persist Social Security numbers.",
    require={"forbidden_substrings": ["ssn"]},
)


def builtin_policies() -> list[Policy]:
    """Default policies applied automatically (empty: checks provide defaults)."""
    return []


def example_policies() -> list[Policy]:
    """A couple of ready-made policies users can opt into."""
    return [NO_SSN]


__all__ = [
    "NO_SSN",
    "builtin_policies",
    "example_policies",
]
