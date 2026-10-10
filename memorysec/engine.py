"""Run every check over stored records and build a `ScanReport`.

A check can add findings. It cannot hide a finding another check already
raised. If a check raises and `fail_closed` is on, that error becomes a
`check_error` finding instead of being skipped.

Both `MemorySec` and `AsyncMemorySec` use this engine.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from .checks.base import MemoryCheck
from .config import Config
from .context import CheckContext
from .models.enums import Action, Category, Severity
from .models.finding import Finding
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import ScanFinding, ScanReport
from .scan.mask import mask_snippet
from .scan.owasp import ASI06_REF
from .telemetry import (
    ATTR_FINDING_COUNT,
    ATTR_OPERATION,
    SPAN_SCAN,
    NullTracer,
    Tracer,
    get_logger,
)

_logger = get_logger(__name__)


class Evaluator:
    """Run the check list and collect a `ScanReport`.

    Attributes:
        config: Settings for this scan, including `fail_closed`.
        checks: Checks to run, in order, on every record.
        tracer: Receives one span per scan. A missing tracer is replaced
            with `NullTracer`, which records nothing.
    """

    def __init__(
        self,
        *,
        config: Config,
        checks: list[MemoryCheck],
        tracer: Tracer | None = None,
    ) -> None:
        """Store the settings, checks, and tracer used by `scan`.

        Args:
            config: Settings for this scan.
            checks: Checks to run on every record, in this order.
            tracer: Span destination. `None` means record nothing.
        """
        self.config = config
        self.checks = checks
        self.tracer: Tracer = tracer or NullTracer()

    def scan(self, records: Iterable[MemoryRecord], *, query: str | None = None) -> ScanReport:
        """Audit stored records for poisoned facts, hidden instructions, and secrets.

        Args:
            records: Memories to scan. A list or tuple is one batch, so each
                check sees the other records as `context.existing`. A streaming
                iterable is not stored first, so `context.existing` stays empty.
            query: The retrieval question for this batch. Passed through as
                `context.query`. Most checks ignore it.

        Returns:
            A `ScanReport`. `total` is how many records were read. `findings`
            lists each problem, highest severity first. Secret text in snippets
            is masked.
        """
        now = datetime.now(UTC)
        batch = list(records) if isinstance(records, Sequence) else None
        stream: Iterable[MemoryRecord] = batch if batch is not None else records
        ctx = CheckContext(
            config=self.config,
            now=now,
            operation="scan",
            existing=list(batch) if batch is not None else [],
            query=query,
        )
        report = ScanReport(generated_at=now)
        with self.tracer.span(SPAN_SCAN, {ATTR_OPERATION: "scan"}) as span:
            finding_count = 0
            for record in stream:
                report.total += 1
                candidate = MemoryCandidate(
                    content=record.content,
                    metadata=dict(record.metadata),
                    id=record.id,
                    derived_from=list(record.derived_from),
                    created_at=record.created_at,
                )
                findings = self._run_checks(candidate, ctx)
                finding_count += len(findings)
                snippet = mask_snippet(record.content)
                for finding in findings:
                    report.findings.append(
                        ScanFinding(
                            id=record.id,
                            type=finding.code,
                            severity=finding.severity,
                            detectors=_detectors(finding),
                            snippet=snippet,
                            action=_report_action(finding.recommended_action, finding.severity),
                            owasp=ASI06_REF,
                            message=finding.message,
                        )
                    )
            report.findings.sort(key=lambda item: item.severity.rank, reverse=True)
            span.set_attribute("memorysec.scanned", report.total)
            span.set_attribute("memorysec.flagged", report.flagged)
            span.set_attribute(ATTR_FINDING_COUNT, finding_count)
        return report

    def _run_checks(self, candidate: MemoryCandidate, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for chk in self.checks:
            name = getattr(chk, "name", None)
            try:
                for finding in chk.check(candidate, ctx):
                    if finding.check is None and isinstance(name, str):
                        finding = finding.model_copy(update={"check": name})
                    findings.append(finding)
            except Exception as exc:
                _logger.warning(
                    "check {!r} raised {}", getattr(chk, "name", chk), type(exc).__name__
                )
                if self.config.fail_closed:
                    findings.append(
                        Finding(
                            code="check_error",
                            category=Category.SECURITY,
                            severity=Severity.CRITICAL,
                            message=(
                                f"Check '{getattr(chk, 'name', 'unknown')}' failed; failing closed."
                            ),
                            evidence={"error_type": type(exc).__name__},
                            check="core",
                            recommended_action=Action.DELETE,
                        )
                    )
        return findings


def _detectors(finding: Finding) -> list[str]:
    raw = finding.evidence.get("detectors")
    if isinstance(raw, list):
        return [str(name) for name in raw]
    if finding.check:
        return [finding.check]
    return []


def _report_action(action: Action | None, severity: Severity) -> Action:
    """Pick review, quarantine, or delete for one finding.

    Args:
        action: The action the check recommended. Used as-is when it is
            already review, quarantine, or delete.
        severity: Used when `action` is missing or is some other value.
            Critical becomes delete, high becomes quarantine, and anything
            lower becomes review.

    Returns:
        The action written on the scan finding.
    """
    if action in {Action.REVIEW, Action.QUARANTINE, Action.DELETE}:
        return action
    if severity.is_at_least(Severity.CRITICAL):
        return Action.DELETE
    if severity.is_at_least(Severity.HIGH):
        return Action.QUARANTINE
    return Action.REVIEW


__all__ = ["Evaluator"]
