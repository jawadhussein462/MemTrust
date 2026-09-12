"""Declarative :class:`Policy` model.

Policies are intentionally small and data-only. Anything a declarative policy
cannot express cleanly should be written as a plain Python callable instead
(see :mod:`memtrust.policies`). We deliberately do *not* ship a policy DSL.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import Action, Severity


class Policy(BaseModel):
    """A declarative rule: *when* some conditions hold, *require* something.

    Supported ``when`` keys: ``tenant_id``, ``namespace``, ``namespace_in``
    (list), ``source_type``, ``source_trust_at_most`` (trust level name).
    An empty ``when`` matches everything.

    Supported ``require`` keys: ``minimum_authority`` (float 0..1),
    ``allowed_trust`` (list of trust level names).

    Example::

        Policy(
            name="finance-policy-authority",
            when={"namespace": "finance_policy"},
            require={"minimum_authority": 0.9},
        )
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    when: dict[str, object] = Field(default_factory=dict)
    require: dict[str, object] = Field(default_factory=dict)
    action: Action | None = Field(
        default=None, description="Explicit action if the requirement is violated (default: block)."
    )
    severity: Severity = Field(default=Severity.HIGH)


__all__ = ["Policy"]
