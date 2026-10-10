"""What `Mimvo.scan` gives back: `ScanFinding` rows and a `ScanReport`."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from .._version import __version__
from ..rules import rule_for
from .enums import Action, Severity

SCHEMA_VERSION = "2.0"
"""Version of the JSON report layout. Bumped when fields change meaning."""


def finding_fingerprint(record_id: str, code: str) -> str:
    """Stable id for one finding on one record, for baselines and dedupe.

    The same rule on the same record gets the same fingerprint on every
    scan, so a ticket, a SARIF alert, or a suppression list can track it.
    Only the record id and the rule are hashed, never the memory text.

    Args:
        record_id: Id of the stored record.
        code: Finding code, such as `"secret_detected"`.

    Returns:
        32 hex characters.
    """
    return hashlib.sha256(f"{code}\x1f{record_id}".encode()).hexdigest()[:32]


class ScanFinding(BaseModel):
    """One problem in a stored record, safe to forward.

    The snippet is secret-masked. The raw memory text is not included.

    Attributes:
        id: Id of the stored record.
        type: Finding code, such as `"secret_detected"`. This is the rule id.
        severity: How serious this row is.
        detectors: Names of the detectors that agreed on it.
        snippet: A short, masked excerpt of the record.
        action: Recommended next step: review, quarantine, or delete.
        owasp: OWASP reference. Secrets and PII use LLM02; injection uses
            LLM01; poisoning uses ASI06.
        message: The sentence from the check, explaining the hit.
        check: Name of the check that raised it, such as `"secrets"`.
        title: Short human title for the rule, such as `"Leaked secret"`.
            Filled from the rule catalogue when left empty.
        remediation: Steps to fix it, from the rule catalogue.
        cwe: CWE ids for the weakness, such as `["CWE-312"]`.
        evidence: Why it was flagged: kinds, matched phrases, scores. Strings
            are masked; raw secrets and full text are never included.
        fingerprint: Stable hash of rule and record id. See
            `finding_fingerprint`.
        confidence: Combined detector confidence from 0 to 1. Several
            agreeing detectors raise it. `None` when no detector scored
            its hit.
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
    check: str = ""
    title: str = ""
    remediation: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    confidence: float | None = None

    @model_validator(mode="after")
    def _fill_from_rule(self) -> ScanFinding:
        rule = rule_for(self.type)
        if not self.title:
            self.title = rule.title
        if not self.remediation:
            self.remediation = list(rule.remediation)
        if not self.cwe:
            self.cwe = list(rule.cwe)
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(self.id, self.type)
        return self


class ScanError(BaseModel):
    """A check or detector that failed during a scan, grouped across records.

    An error is not a finding. It says the affected records were not fully
    checked, not that anything is wrong with them, so it never adds a
    record to the action plan.

    Attributes:
        check: Name of the check, such as `"injection"`.
        detector: Name of the detector that raised, or `None` when the
            whole check raised.
        error_type: Exception class name, such as `"BackendError"`.
        message: The first error message, secret-masked and shortened.
        records: How many records hit this error.
        record_ids: The first few affected record ids.
    """

    model_config = ConfigDict(extra="forbid")

    check: str
    detector: str | None = None
    error_type: str
    message: str = ""
    records: int = 0
    record_ids: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """The result of `Mimvo.scan`.

    Counts every record read and lists each problem (poisoned fact, hidden
    instruction, leaked secret) with a recommended action.

    Attributes:
        schema_version: Layout version of the JSON form of this report.
        mimvo_version: Mimvo version that produced it.
        total: How many records were read.
        findings: One `ScanFinding` per problem, not per record. A record
            can appear more than once if it has several problems.
        source: Label of where the records came from, such as
            `"chroma:agent_memory"`. Empty when the caller did not set it.
        sample: Cap on how many records were requested. `None` means the
            scan was not capped.
        generated_at: When the scan started, in UTC. `None` if not set.
        duration_seconds: How long the checks took. `None` if not measured.
        checks: Each check that ran, mapped to its detector names, so a
            reader can tell what was looked for as well as what was found.
        errors: Checks and detectors that failed, grouped by check,
            detector, and exception type. Empty on a complete scan.
        records_with_errors: Distinct records at least one check or
            detector failed on.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: str = SCHEMA_VERSION
    mimvo_version: str = __version__
    total: int = 0
    findings: list[ScanFinding] = Field(default_factory=list)
    source: str = ""
    sample: int | None = None
    generated_at: datetime | None = None
    duration_seconds: float | None = None
    checks: dict[str, list[str]] = Field(default_factory=dict)
    errors: list[ScanError] = Field(default_factory=list)
    records_with_errors: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def complete(self) -> bool:
        """Whether every check and detector ran on every record.

        Returns:
            `False` when any check or detector raised. Findings from the
            parts that did run are still in `findings`, but a record with
            no finding may not have been fully checked. The CLI exits `2`
            on an incomplete scan.
        """
        return not self.errors

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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def by_rule(self) -> dict[str, int]:
        """Count findings by finding code, most frequent first.

        Returns:
            A dict such as `{"memory_poisoning": 3, "secret_detected": 1}`.
        """
        counts: dict[str, int] = {}
        for item in self.findings:
            counts[item.type] = counts.get(item.type, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def by_action(self) -> dict[str, int]:
        """Count flagged records by the strongest action they need.

        A record with a `delete` finding and a `review` finding counts once,
        under `delete`. The counts add up to `flagged`.

        Returns:
            A dict such as `{"delete": 1, "quarantine": 1, "review": 2}`.
            Actions with no records are omitted.
        """
        return {action.value: len(ids) for action, ids in self.action_plan().items() if ids}

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

    def action_plan(self) -> dict[Action, list[str]]:
        """Group flagged records by the strongest action each one needs.

        This is the to-do list a report opens with: which records to
        delete, which to quarantine, which to review.

        Returns:
            Delete, quarantine, and review, in that order, each mapped to
            record ids in report order. Every flagged record appears once.
        """
        strongest: dict[str, Action] = {}
        for item in self.findings:
            current = strongest.get(item.id)
            if current is None or item.action.precedence > current.precedence:
                strongest[item.id] = item.action
        plan: dict[Action, list[str]] = {
            Action.DELETE: [],
            Action.QUARANTINE: [],
            Action.REVIEW: [],
        }
        for record_id, action in strongest.items():
            plan[action].append(record_id)
        return plan

    def at_or_above(
        self, severity: Severity, *, min_confidence: float | None = None
    ) -> list[ScanFinding]:
        """Findings as serious as `severity`, or worse.

        Args:
            severity: The threshold, such as `Severity.HIGH`.
            min_confidence: Also drop findings whose confidence is below
                this. Findings with no confidence (`None`) are kept, so an
                unscored detector is never silently ignored.

        Returns:
            The matching findings, in report order. This is what the CLI's
            `--fail-on` and `--min-confidence` gate on.
        """
        return [
            item
            for item in self.findings
            if item.severity.is_at_least(severity)
            and (
                min_confidence is None
                or item.confidence is None
                or item.confidence >= min_confidence
            )
        ]

    def __str__(self) -> str:
        return format_scan_summary(self)


_RESET = "\033[0m"
_GREEN = "\033[32m"
_RED = "\033[31m"
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
    details: bool = False,
    max_rows: int = 20,
    outputs: Sequence[tuple[str, str]] = (),
) -> str:
    """Build the text printed after a scan.

    The lines are: how many records were scanned, how many were flagged,
    a count per severity, optionally a findings table, then the files that
    were written.

    Args:
        report: The scan result to summarize.
        report_path: HTML file that was written. Omitted from the text
            when `None`.
        json_path: JSON file that was written. Omitted when `None`.
        color: When `True`, wrap marks in ANSI color: green checks, an
            amber flag, and a colored dot per severity. When `False`,
            return plain text.
        details: When `True`, add a table of findings (severity, rule,
            record id, action, confidence, OWASP) under the counts. Memory
            text is never printed, so the table is safe for CI logs.
        max_rows: Most table rows to print before summarising the rest.
        outputs: More written files as `(label, path)` pairs, such as
            `("SARIF", "results.sarif")`, listed after the JSON file.

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
    if report.errors:
        cross = _paint("✗", _RED, enabled=color)
        lines.append(
            f"{cross} Scan incomplete: {_records(report.records_with_errors)} not fully checked"
        )
        for error in report.errors[:3]:
            where = error.check + (f"/{error.detector}" if error.detector else "")
            lines.append(f"  • {where} raised {error.error_type} on {_records(error.records)}")
        if len(report.errors) > 3:
            lines.append(f"  • … {len(report.errors) - 3} more in the report")

    if details and report.findings:
        lines.append("")
        lines.extend(_findings_table(report, color=color, max_rows=max_rows))

    written: list[str] = []
    if report_path:
        path = _paint(report_path, _UNDERLINE, enabled=color)
        written.append(f"{check} Report written to {path}")
    if json_path:
        written.append(
            f"{check} Findings written to {_paint(json_path, _UNDERLINE, enabled=color)}"
        )
    for label, out_path in outputs:
        written.append(f"{check} {label} written to {_paint(out_path, _UNDERLINE, enabled=color)}")
    if written:
        lines.append("")
        lines.extend(written)
    return "\n".join(lines)


_DIM = "\033[2m"
_ID_WIDTH = 28


def _findings_table(report: ScanReport, *, color: bool, max_rows: int) -> list[str]:
    """Render findings as aligned columns, worst first.

    Args:
        report: The scan result. Findings are already sorted by severity.
        color: Paint the severity column and dim the header.
        max_rows: Rows to show before a "more in the report" line.

    Returns:
        Lines of text, each indented by two spaces.
    """
    rows = [
        (
            item.severity.value,
            item.type,
            _clip(item.id, _ID_WIDTH),
            item.action.value,
            "—" if item.confidence is None else f"{item.confidence:.2f}",
            item.owasp.split(":", 1)[0],
        )
        for item in report.findings[: max(max_rows, 0)]
    ]
    header = ("SEVERITY", "RULE", "RECORD", "ACTION", "CONF", "OWASP")
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]

    def line(cells: tuple[str, ...], *, sev: str | None = None) -> str:
        padded = [cell.ljust(widths[i]) for i, cell in enumerate(cells)]
        if sev is not None:
            padded[0] = _paint(padded[0], _SEVERITY_COLOR.get(sev, ""), enabled=color)
        return "  " + "  ".join(padded).rstrip()

    out = [_paint(line(header), _DIM, enabled=color)]
    out.extend(line(row, sev=row[0]) for row in rows)
    hidden = len(report.findings) - len(rows)
    if hidden > 0:
        noun = "finding" if hidden == 1 else "findings"
        out.append(_paint(f"  … {hidden:,} more {noun}", _DIM, enabled=color))
    return out


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


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
    if not enabled or not code:
        return text
    return f"{code}{text}{_RESET}"


__all__ = [
    "SCHEMA_VERSION",
    "ScanError",
    "ScanFinding",
    "ScanReport",
    "finding_fingerprint",
    "format_scan_summary",
]
