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
        # Two decimals so a large store reads 0.28%, not 0.3%.
        return round(100.0 * self.flagged / self.total, 2)

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
        return format_scan_summary(self)


_RESET = "\033[0m"
_GREEN = "\033[32m"
_AMBER = "\033[38;5;214m"
_UNDERLINE = "\033[4m"
_SEVERITY_COLOR = {
    "critical": "\033[31m",
    "high": "\033[38;5;208m",
    "medium": "\033[33m",
    "low": "\033[38;5;67m",
    "info": "\033[90m",
}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def format_scan_summary(
    report: ScanReport,
    *,
    report_path: str | None = None,
    json_path: str | None = None,
    color: bool = False,
) -> str:
    """Terminal summary: scanned, flagged, severity, then files written.

    Plain text by default. ``color=True`` paints the marks the way a terminal
    does: green checks, an amber flag, and a colored dot per severity.
    """
    check = _paint("✓", _GREEN, enabled=color)
    lines = [f"{check} Scanned {_records(report.total)}"]
    if report.flagged:
        bang = _paint("!", _AMBER, enabled=color)
        lines.append(f"{bang} {_records(report.flagged)} flagged ({report.flagged_pct:.2f}%)")
        severity = _severity_line(report, color=color)
        if severity:
            lines.append(severity)
    else:
        lines.append(f"{check} {_records(0)} flagged")

    written: list[str] = []
    if report_path:
        path = _paint(report_path, _UNDERLINE, enabled=color)
        written.append(f"{check} Report written to {path}")
    if json_path:
        written.append(
            f"{check} Findings written to {_paint(json_path, _UNDERLINE, enabled=color)}"
        )
    if written:
        lines.append("")
        lines.extend(written)
    return "\n".join(lines)


def _records(n: int) -> str:
    noun = "record" if n == 1 else "records"
    return f"{n:,} {noun}"


def _severity_line(report: ScanReport, *, color: bool) -> str:
    counts = report.by_severity
    parts: list[str] = []
    for name in _SEVERITY_ORDER:
        count = counts.get(name, 0)
        if not count:
            continue
        label = f"• {count:,} {name}"
        parts.append(_paint(label, _SEVERITY_COLOR[name], enabled=color))
    if not parts:
        return ""
    return "  " + "  ".join(parts)


def _paint(text: str, code: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{_RESET}"


__all__ = [
    "ScanFinding",
    "ScanReport",
    "format_scan_summary",
]
