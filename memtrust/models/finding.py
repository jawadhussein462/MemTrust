"""A single :class:`Finding` produced by a check or policy."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import Action, Category, Severity


class Finding(BaseModel):
    """One thing a check or policy noticed about a memory.

    A finding never decides the outcome on its own; the decision engine
    aggregates all findings (and the enforcement mode) into a single
    :class:`~memtrust.Decision`.

    Example::

        Finding(
            code="memory_poisoning",
            category="security",
            severity="critical",
            message="Content looks like an attempt to plant a false security fact.",
        )
    """

    model_config = ConfigDict(extra="forbid")

    code: str = Field(description="Stable machine-readable identifier, e.g. 'memory_poisoning'.")
    category: Category = Field(default=Category.SECURITY)
    severity: Severity = Field(default=Severity.MEDIUM)
    message: str = Field(description="Human-readable explanation.")
    evidence: dict[str, object] = Field(
        default_factory=dict,
        description="Structured, non-sensitive supporting data. Never contains raw secrets.",
    )
    check: str | None = Field(
        default=None, description="Name of the check/policy that raised this."
    )
    recommended_action: Action | None = Field(
        default=None,
        description="Action this finding argues for; the engine aggregates across findings.",
    )

    def __str__(self) -> str:
        return f"{self.severity.value.upper():<8} {self.code} — {self.message}"


__all__ = ["Finding"]
