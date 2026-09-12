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

    Supported ``when`` keys: metadata field names whose values must match
    ``candidate.metadata``. An empty ``when`` matches everything.

    Supported ``require`` keys: ``forbidden_substrings`` (list of strings that
    must not appear in the candidate content).

    Example::

        Policy(
            name="no-ssn",
            require={"forbidden_substrings": ["ssn"]},
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
