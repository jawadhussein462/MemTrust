"""The evaluation engine.

Holds decision aggregation *and* the non-bypassable core enforcement
(revoked/expired/quarantined/superseded filtering on read).
Pluggable checks run on top; they can add findings but cannot remove core
protections. Checks declaring the ``read`` operation also run on every
retrieved record that passes core enforcement, so poisoned or injected
content that reached the store some other way is still withheld.

Shared by both :class:`~memtrust.MemTrust` and
:class:`~memtrust.AsyncMemTrust`; backend I/O lives in the client wrappers.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

from .checks.base import MemoryCheck, check_operations
from .config import Config
from .context import CheckContext
from .models.decision import Decision
from .models.enums import (
    Action,
    Category,
    MemoryStatus,
    Risk,
    Severity,
)
from .models.finding import Finding
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import FilteredMemory, ReadResult, SafeMemory, ScanFinding, ScanReport
from .telemetry import (
    ATTR_ACTION,
    ATTR_FINDING_COUNT,
    ATTR_OPERATION,
    ATTR_RISK,
    SPAN_READ_CHECK,
    SPAN_SCAN,
    SPAN_WRITE_CHECK,
    NullTracer,
    Tracer,
    get_logger,
)
from .text import normalize

_logger = get_logger(__name__)

# Fallback action when a finding has no explicit recommendation.
_RISK_TO_ACTION: dict[Risk, Action] = {
    Risk.NONE: Action.ALLOW,
    Risk.INFO: Action.ALLOW,
    Risk.LOW: Action.ALLOW_WITH_WARNING,
    Risk.MEDIUM: Action.ALLOW_WITH_WARNING,
    Risk.HIGH: Action.BLOCK,
    Risk.CRITICAL: Action.BLOCK,
}


class Evaluator:
    """Runs checks and produces decisions and safe read results."""

    def __init__(
        self,
        *,
        config: Config,
        checks: list[MemoryCheck],
        tracer: Tracer | None = None,
    ) -> None:
        self.config = config
        self.checks = checks
        self.write_checks = [c for c in checks if "write" in check_operations(c)]
        self.read_checks = [c for c in checks if "read" in check_operations(c)]
        self.tracer: Tracer = tracer or NullTracer()

    # -- write ------------------------------------------------------------------

    def evaluate_write(
        self,
        candidate: MemoryCandidate,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        now = datetime.now(UTC)
        ctx = CheckContext(
            config=self.config,
            now=now,
            operation="write",
            existing=existing or [],
        )

        with self.tracer.span(
            SPAN_WRITE_CHECK,
            {ATTR_OPERATION: "write"},
        ) as span:
            findings = self._run_checks(self.write_checks, candidate, ctx)

            decision = aggregate(findings)

            span.set_attribute(ATTR_ACTION, decision.action.value)
            span.set_attribute(ATTR_RISK, decision.risk.value)
            span.set_attribute(ATTR_FINDING_COUNT, len(findings))

            return decision

    def _run_checks(
        self, checks: list[MemoryCheck], candidate: MemoryCandidate, ctx: CheckContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        for chk in checks:
            try:
                findings.extend(chk.check(candidate, ctx))
            except Exception as exc:
                _logger.warning("check %r raised %s", getattr(chk, "name", chk), type(exc).__name__)
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
                            recommended_action=Action.BLOCK,
                        )
                    )
        return findings

    # -- read -------------------------------------------------------------------

    def evaluate_read(self, records: list[MemoryRecord], *, query: str | None = None) -> ReadResult:
        """Filter ``records`` down to those safe to return.

        ``query`` is the retrieval query when known; the rest of the read set
        is exposed to read checks as ``context.existing`` so retrieval-aware
        detectors (FilterRAG, TrustRAG) can reason about the batch.
        """
        now = datetime.now(UTC)
        with self.tracer.span(
            SPAN_READ_CHECK,
            {ATTR_OPERATION: "read"},
        ) as span:
            result = ReadResult()
            ctx = CheckContext(
                config=self.config,
                now=now,
                operation="read",
                existing=list(records),
                query=query,
            )
            for record in records:
                finding = self._core_read_finding(record, now)
                if finding is not None:
                    result.filtered.append(FilteredMemory(record=record, finding=finding))
                    result.findings.append(finding)
                    continue
                findings = self._read_check_findings(record, ctx)
                result.findings.extend(findings)
                decision = aggregate(findings)
                if not decision.allowed and decision.top_finding is not None:
                    result.filtered.append(
                        FilteredMemory(record=record, finding=decision.top_finding)
                    )
                    continue
                result.results.append(SafeMemory(record=record))

            span.set_attribute("memtrust.returned", len(result.results))
            span.set_attribute("memtrust.filtered", len(result.filtered))
            return result

    def scan(self, records: Iterable[MemoryRecord]) -> ScanReport:
        """Audit stored records without I/O: what reads would withhold, and why."""
        now = datetime.now(UTC)
        ctx = CheckContext(config=self.config, now=now, operation="read")
        report = ScanReport()
        by_text: dict[str, list[str]] = defaultdict(list)
        with self.tracer.span(SPAN_SCAN, {ATTR_OPERATION: "scan"}) as span:
            for record in records:
                report.total += 1
                status = MemoryStatus.EXPIRED if record.is_expired(now) else record.status
                report.by_status[status.value] = report.by_status.get(status.value, 0) + 1
                if self._core_read_finding(record, now) is not None:
                    continue
                findings = self._read_check_findings(record, ctx)
                for f in findings:
                    report.by_code[f.code] = report.by_code.get(f.code, 0) + 1
                decision = aggregate(findings)
                if not decision.allowed:
                    codes = sorted({f.code for f in findings})
                    report.flagged.append(
                        ScanFinding(id=record.id, codes=codes, action=decision.action)
                    )
                    continue
                report.served += 1
                by_text[normalize(record.content)].append(record.id)
            report.duplicate_groups = [ids for ids in by_text.values() if len(ids) > 1]
            span.set_attribute("memtrust.scanned", report.total)
            span.set_attribute("memtrust.flagged", len(report.flagged))
        return report

    def _read_check_findings(self, record: MemoryRecord, ctx: CheckContext) -> list[Finding]:
        if not self.config.read_checks or not self.read_checks:
            return []
        candidate = MemoryCandidate(
            content=record.content,
            metadata=dict(record.metadata),
            id=record.id,
            derived_from=list(record.derived_from),
            created_at=record.created_at,
            expires_at=record.expires_at,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
        )
        return self._run_checks(self.read_checks, candidate, ctx)

    def _core_read_finding(self, record: MemoryRecord, now: datetime) -> Finding | None:
        """Non-bypassable read enforcement; returns a Finding if withheld."""
        if record.status == MemoryStatus.REVOKED:
            return Finding(
                code="memory_revoked",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                message="Memory has been revoked.",
                check="core",
            )
        if record.status == MemoryStatus.QUARANTINED:
            return Finding(
                code="memory_quarantined",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                message="Memory is quarantined.",
                check="core",
            )
        if record.status == MemoryStatus.SUPERSEDED:
            return Finding(
                code="memory_superseded",
                category=Category.CORRECTNESS,
                severity=Severity.LOW,
                message="Memory has been superseded by a newer version.",
                check="core",
            )
        if record.is_expired(now):
            return Finding(
                code="memory_expired",
                category=Category.CORRECTNESS,
                severity=Severity.LOW,
                message="Memory has expired.",
                check="core",
            )
        if record.is_not_yet_valid(now):
            return Finding(
                code="memory_not_yet_valid",
                category=Category.CORRECTNESS,
                severity=Severity.LOW,
                message="Memory is not yet valid.",
                check="core",
            )
        return None


def aggregate(findings: list[Finding]) -> Decision:
    """Combine findings into a single Decision."""
    if not findings:
        return Decision(
            allowed=True,
            action=Action.ALLOW,
            recommended_action=Action.ALLOW,
            risk=Risk.NONE,
            findings=[],
        )

    worst = max((f.severity for f in findings), key=lambda s: s.rank)
    risk = Risk.from_severity(worst)

    # Every finding contributes an action: its explicit recommendation, or the
    # action implied by its severity. This ensures a CRITICAL/HIGH finding
    # forces a blocking action even when it (or a custom check) omits an
    # explicit recommendation, and it cannot be masked by another finding that
    # happens to recommend an allowed action (security: severity drives risk).
    def _finding_action(finding: Finding) -> Action:
        if finding.recommended_action is not None:
            return finding.recommended_action
        return _RISK_TO_ACTION[Risk.from_severity(finding.severity)]

    action = max((_finding_action(f) for f in findings), key=lambda a: a.precedence)

    supersedes: list[str] = []
    if action.is_allowed:
        for f in findings:
            if f.recommended_action == Action.SUPERSEDE:
                ids = f.evidence.get("supersedes", [])
                if isinstance(ids, list):
                    supersedes.extend(str(i) for i in ids)

    return Decision(
        allowed=action.is_allowed,
        action=action,
        recommended_action=action,
        risk=risk,
        findings=findings,
        supersedes=sorted(set(supersedes)),
    )


__all__ = ["Evaluator", "aggregate"]
