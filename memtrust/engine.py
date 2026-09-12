"""The evaluation engine.

Holds the mode-independent decision logic *and* the non-bypassable core
enforcement (revoked/expired/quarantined/superseded filtering on read).
Pluggable checks and policies run on top; they can add findings but cannot
remove core protections.

Shared by both :class:`~memtrust.MemTrust` and
:class:`~memtrust.AsyncMemTrust`; backend I/O lives in the client wrappers.
"""

from __future__ import annotations

from datetime import datetime

from .audit.base import AuditEvent, AuditStore
from .checks.base import MemoryCheck
from .clock import Clock
from .config import Config
from .context import CheckContext
from .models.decision import Decision
from .models.enums import (
    Action,
    AuditEventType,
    Category,
    MemoryStatus,
    Mode,
    Risk,
    Severity,
)
from .models.finding import Finding
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import FilteredMemory, ReadResult, SafeMemory
from .policies.engine import PolicyEngine
from .redaction import redact_text
from .semantic.base import SemanticAnalyzer
from .telemetry import (
    ATTR_ACTION,
    ATTR_FINDING_COUNT,
    ATTR_MODE,
    ATTR_OPERATION,
    ATTR_RISK,
    SPAN_READ_CHECK,
    SPAN_WRITE_CHECK,
    NullTracer,
    Tracer,
    get_logger,
)

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
    """Runs checks/policies and produces decisions and safe read results."""

    def __init__(
        self,
        *,
        config: Config,
        checks: list[MemoryCheck],
        policy_engine: PolicyEngine,
        semantic: SemanticAnalyzer,
        audit: AuditStore,
        clock: Clock,
        tracer: Tracer | None = None,
    ) -> None:
        self.config = config
        self.checks = checks
        self.policy_engine = policy_engine
        self.semantic = semantic
        self.audit = audit
        self.clock = clock
        self.tracer: Tracer = tracer or NullTracer()

    # -- write ------------------------------------------------------------------

    def evaluate_write(
        self,
        candidate: MemoryCandidate,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        now = self.clock.now()
        ctx = CheckContext(
            config=self.config,
            semantic=self.semantic,
            now=now,
            operation="write",
            existing=existing or [],
        )

        with self.tracer.span(
            SPAN_WRITE_CHECK,
            {ATTR_OPERATION: "write", ATTR_MODE: self.config.mode.value},
        ) as span:
            self._emit(AuditEventType.WRITE_REQUESTED, candidate=candidate)

            findings: list[Finding] = []
            findings.extend(self._run_checks(candidate, ctx))
            matched, policy_findings = self.policy_engine.evaluate(candidate, ctx)
            findings.extend(policy_findings)

            decision = aggregate(findings, self.config.mode, policy_matches=matched)

            span.set_attribute(ATTR_ACTION, decision.action.value)
            span.set_attribute(ATTR_RISK, decision.risk.value)
            span.set_attribute(ATTR_FINDING_COUNT, len(findings))

            self._emit_write_outcome(candidate, decision)
            return decision

    def _run_checks(self, candidate: MemoryCandidate, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for chk in self.checks:
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

    def evaluate_read(self, records: list[MemoryRecord]) -> ReadResult:
        now = self.clock.now()
        with self.tracer.span(
            SPAN_READ_CHECK,
            {ATTR_OPERATION: "read", ATTR_MODE: self.config.mode.value},
        ) as span:
            self._emit(AuditEventType.READ_REQUESTED)

            result = ReadResult()
            for record in records:
                finding = self._core_read_finding(record, now)
                if finding is not None:
                    result.filtered.append(FilteredMemory(record=record, finding=finding))
                    result.findings.append(finding)
                    self._emit(
                        AuditEventType.READ_FILTERED,
                        memory_id=record.id,
                        finding_codes=[finding.code],
                        risk=Risk.from_severity(finding.severity),
                    )
                    continue
                result.results.append(SafeMemory(record=record))
                self._emit(
                    AuditEventType.READ_ALLOWED,
                    memory_id=record.id,
                )

            span.set_attribute("memtrust.returned", len(result.results))
            span.set_attribute("memtrust.filtered", len(result.filtered))
            return result

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

    # -- audit ------------------------------------------------------------------

    def log_event(
        self,
        event_type: AuditEventType,
        *,
        memory_id: str | None = None,
    ) -> None:
        """Public helper to record lifecycle events (supersede/revoke)."""
        self._emit(event_type, memory_id=memory_id)

    def _emit(
        self,
        event_type: AuditEventType,
        *,
        candidate: MemoryCandidate | None = None,
        memory_id: str | None = None,
        finding_codes: list[str] | None = None,
        risk: Risk | None = None,
    ) -> None:
        preview = None
        if candidate is not None:
            preview = self._content_preview(candidate.content)
        event = AuditEvent(
            type=event_type,
            memory_id=memory_id,
            finding_codes=finding_codes or [],
            finding_count=len(finding_codes or []),
            risk=risk,
            content_preview=preview,
        )
        self.audit.append(event)

    def _emit_write_outcome(self, candidate: MemoryCandidate, decision: Decision) -> None:
        if decision.action == Action.QUARANTINE:
            event_type = AuditEventType.WRITE_QUARANTINED
        elif decision.allowed:
            event_type = AuditEventType.WRITE_ALLOWED
        else:
            event_type = AuditEventType.WRITE_BLOCKED
        self.audit.append(
            AuditEvent(
                type=event_type,
                action=decision.action,
                risk=decision.risk,
                finding_codes=decision.finding_codes(),
                finding_count=len(decision.findings),
                policy_matches=decision.policy_matches,
                content_preview=self._content_preview(candidate.content),
            )
        )

    def _content_preview(self, content: str) -> str | None:
        if not self.config.audit_content:
            return None
        redacted, _ = redact_text(content)
        return redacted[: self.config.audit_content_max_len]


def aggregate(
    findings: list[Finding], mode: Mode, *, policy_matches: list[str] | None = None
) -> Decision:
    """Combine findings + mode into a single Decision."""
    policy_matches = policy_matches or []
    if not findings:
        return Decision(
            allowed=True,
            action=Action.ALLOW,
            recommended_action=Action.ALLOW,
            risk=Risk.NONE,
            findings=[],
            mode=mode,
            enforced=(mode == Mode.ENFORCE),
            policy_matches=policy_matches,
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

    recommended = max((_finding_action(f) for f in findings), key=lambda a: a.precedence)

    # Apply enforcement mode to get the effective action.
    if mode == Mode.ENFORCE:
        effective = recommended
        enforced = True
    elif mode == Mode.WARN:
        effective = Action.ALLOW_WITH_WARNING if risk != Risk.NONE else Action.ALLOW
        enforced = False
    else:  # OBSERVE
        effective = Action.ALLOW
        enforced = False

    # Corrective effects (supersede/rewrite) apply only when enforcing AND the
    # write is actually allowed to proceed. Both can apply together (e.g. a
    # newer fact that also contained a secret).
    supersedes: list[str] = []
    rewritten: str | None = None
    if mode == Mode.ENFORCE and effective.is_allowed:
        for f in findings:
            if f.recommended_action == Action.SUPERSEDE:
                ids = f.evidence.get("supersedes", [])
                if isinstance(ids, list):
                    supersedes.extend(str(i) for i in ids)
        for f in sorted(findings, key=lambda f: f.severity.rank, reverse=True):
            if f.recommended_action == Action.REWRITE:
                value = f.evidence.get("rewritten_content")
                if isinstance(value, str):
                    rewritten = value
                    break

    return Decision(
        allowed=effective.is_allowed,
        action=effective,
        recommended_action=recommended,
        risk=risk,
        findings=findings,
        supersedes=sorted(set(supersedes)),
        rewritten_content=rewritten,
        policy_matches=policy_matches,
        mode=mode,
        enforced=enforced,
    )


__all__ = ["Evaluator", "aggregate"]
