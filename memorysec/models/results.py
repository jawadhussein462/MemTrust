"""What `MemorySec.scan` gives back: `ScanFinding` rows and a `ScanReport`."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from .enums import Action, Severity


class ScanFinding(BaseModel):
    """One problem in a stored record, safe to forward.

    The snippet is secret-masked. The raw memory text is not included.

    Attributes:
        id: Id of the stored record.
        type: Finding code, such as `"secret_detected"`.
        severity: How serious this row is.
        detectors: Names of the detectors that agreed on it.
        snippet: A short, masked excerpt of the record.
        action: Recommended next step: review, quarantine, or delete.
        owasp: OWASP reference. Defaults to ASI06, memory and context poisoning.
        message: The sentence from the check, explaining the hit.
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
    """The result of `MemorySec.scan`.

    Counts every record read and lists each problem (poisoned fact, hidden
    instruction, leaked secret) with a recommended action.

    Attributes:
        total: How many records were read.
        findings: One `ScanFinding` per problem, not per record. A record
            can appear more than once if it has several problems.
        source: Label of where the records came from, such as
            `"chroma:agent_memory"`. Empty when the caller did not set it.
        sample: Cap on how many records were requested. `None` means the
            scan was not capped.
        generated_at: When the scan started, in UTC. `None` if not set.
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
        """How many distinct records have at least one finding.

        Returns:
            The number of unique `id` values in `findings`. A record with
            two problems counts once.
        """
        return len({item.id for item in self.findings})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flagged_pct(self) -> float:
        """Share of scanned records that were flagged, as a percent.

        Returns:
            `100 * flagged / total`, rounded to two decimals so a large
            store reads `0.28` rather than `0.3`. `0.0` when `total` is 0.
        """
        if not self.total:
            return 0.0
        return round(100.0 * self.flagged / self.total, 2)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def by_severity(self) -> dict[str, int]:
        """Count findings by severity name.

        Returns:
            A dict such as `{"high": 2, "critical": 1}`. Severities with
            zero findings are omitted. Keys are the severity strings.
        """
        counts: dict[str, int] = {}
        for item in self.findings:
            key = item.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def clean(self) -> bool:
        """Whether the scan found nothing.

        Returns:
            `True` when `findings` is empty.
        """
        return not self.findings

    def worst_severity(self) -> Severity | None:
        """Return the most serious severity in this report.

        Returns:
            The highest `Severity` among `findings`, or `None` when the
            report has no findings.
        """
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
    """Build the text printed after a scan.

    The lines are: how many records were scanned, how many were flagged,
    a count per severity, then the files that were written.

    Args:
        report: The scan result to summarize.
        report_path: HTML file that was written. Omitted from the text
            when `None`.
        json_path: JSON file that was written. Omitted when `None`.
        color: When `True`, wrap marks in ANSI color: green checks, an
            amber flag, and a colored dot per severity. When `False`,
            return plain text.

    Returns:
        A multi-line string. Print it, or use `str(report)` for the
        plain-text version.
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
