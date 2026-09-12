"""The :class:`Decision` object returned by every write/read check."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import Action, Mode, Risk, Severity
from .finding import Finding


class Decision(BaseModel):
    """The result of evaluating a memory operation.

    Designed to be pleasant to inspect programmatically *and* to print. Do
    not parse strings to understand a decision — use the typed fields and
    convenience properties.

    Example::

        Decision(allowed=False, action="quarantine", risk="critical", findings=[...])
    """

    model_config = ConfigDict(extra="forbid")

    allowed: bool = Field(description="Whether the underlying operation is permitted to proceed.")
    action: Action = Field(description="Effective action after applying the enforcement mode.")
    recommended_action: Action = Field(
        default=Action.ALLOW,
        description="Action the findings argue for, regardless of mode (the 'true' recommendation).",
    )
    risk: Risk = Field(default=Risk.NONE, description="Worst severity across findings.")
    findings: list[Finding] = Field(default_factory=list)
    supersedes: list[str] = Field(
        default_factory=list, description="Record IDs this write should supersede, if any."
    )
    rewritten_content: str | None = Field(
        default=None, description="Redacted/rewritten content to persist when action is 'rewrite'."
    )
    policy_matches: list[str] = Field(
        default_factory=list, description="Names of policies that matched."
    )
    mode: Mode = Field(default=Mode.ENFORCE)
    enforced: bool = Field(
        default=True, description="Whether the mode actively changed the effective action."
    )
    metadata: dict[str, object] = Field(default_factory=dict)

    # -- convenience properties -------------------------------------------------

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def errors(self) -> list[Finding]:
        """Findings at HIGH or CRITICAL severity."""
        return [f for f in self.findings if f.severity.is_at_least(Severity.HIGH)]

    @property
    def warnings(self) -> list[Finding]:
        """Findings below HIGH severity."""
        return [f for f in self.findings if not f.severity.is_at_least(Severity.HIGH)]

    @property
    def top_finding(self) -> Finding | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank)

    @property
    def reason(self) -> str:
        """One-line human explanation of the decision."""
        top = self.top_finding
        if top is not None:
            return top.message
        return "No issues found." if self.allowed else "Operation not permitted."

    def finding_codes(self) -> list[str]:
        return [f.code for f in self.findings]

    def __str__(self) -> str:
        header = "ALLOWED" if self.allowed else "BLOCKED"
        if self.allowed and self.action == Action.ALLOW_WITH_WARNING:
            header = "WARN"
        lines = [f"{header} · {self.risk.value}"]
        if self.findings:
            noun = "finding" if len(self.findings) == 1 else "findings"
            lines.append("")
            lines.append(f"{len(self.findings)} {noun}")
            lines.append("")
            for f in sorted(self.findings, key=lambda f: f.severity.rank, reverse=True):
                lines.append(f"{f.severity.value.upper():<8}  {f.code}")
        lines.append("")
        lines.append(f"Recommended action: {self.recommended_action.value}")
        return "\n".join(lines)


__all__ = ["Decision"]
