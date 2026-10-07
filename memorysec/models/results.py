"""Structured return values for a store scan."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from .enums import Action, Severity


class ScanFinding(BaseModel):
    """One problem in a stored record, safe to forward.

    Snippets are secret-masked. Raw content is never included.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    severity: Severity
    detectors: list[str] = Field(default_factory=list)
    snippet: str = ""
    action: Action
    owasp: str = "ASI06: Memory & Context Poisoning"
    message: str = ""


class ScanReport(BaseModel):
    """Audit of a memory store produced by :meth:`MemorySec.scan`.

    Counts every record examined and lists security findings (poisoned
    facts, hidden instructions, leaked secrets) with a recommended action.
    """

    model_config = ConfigDict(extra="ignore")

    total: int = 0
    findings: list[ScanFinding] = Field(default_factory=list)
    source: str = ""
    sample: int | None = None
    generated_at: datetime | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flagged(self) -> int:
        return len({item.id for item in self.findings})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flagged_pct(self) -> float:
        if not self.total:
            return 0.0
        return round(100.0 * self.flagged / self.total, 1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            key = item.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def clean(self) -> bool:
        return not self.findings

    def worst_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((item.severity for item in self.findings), key=lambda s: s.rank)

    def __str__(self) -> str:
        pct = f"{self.flagged_pct:g}%"
        lines = [f"Scanned {_count(self.total, 'record')}: {self.flagged} flagged ({pct})."]
        if self.by_severity:
            parts = ", ".join(
                f"{count} {name}"
                for name, count in sorted(
                    self.by_severity.items(),
                    key=lambda kv: Severity(kv[0]).rank,
                    reverse=True,
                )
            )
            lines.append(f"By severity: {parts}.")
        if self.findings:
            lines.append("")
            for item in self.findings:
                detectors = ", ".join(item.detectors) if item.detectors else "—"
                lines.append(
                    f"  {item.id}  {item.type}  {item.severity.value}  "
                    f"{item.action.value}  [{detectors}]"
                )
        if self.clean:
            lines.append("No poisoned facts, hidden instructions, or leaked secrets found.")
        return "\n".join(lines)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


__all__ = [
    "ScanFinding",
    "ScanReport",
]
