"""Run every check over stored records and build a `ScanReport`.

A scan has two passes so a large store does not have to sit in memory as
`MemoryRecord` objects:

1. **Stream.** Records are read one at a time. Text-only detectors (the
   phrase lists, secret patterns, classifiers, hosted APIs) run right away,
   and the record is packed into a `Corpus`: its text and metadata, and its
   vector as 4-byte floats.
2. **Corpus.** Detectors that compare records with each other (TrustRAG,
   hubness, NLI, probe queries, and any custom detector that reads
   `context.existing`) run once every record has been read, against one
   shared nearest-neighbour table.

Votes (`min_detectors`) are counted over both passes. A check can add
findings; it cannot hide a finding another check raised.

A check or detector that raises does not stop the scan and does not become
a finding. It is reported in `ScanReport.errors` and the scan is marked
incomplete (`report.complete` is `False`); the other detectors' results
are kept.

Both `Mimvo` and `AsyncMimvo` use this engine.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .checks.base import MemoryCheck
from .checks.security.base import Detection, Detector, SecurityCheck, needs_corpus
from .config import Config
from .context import CheckContext, CheckFailure
from .corpus import Corpus, NeighbourIndex
from .models.enums import Action, Severity
from .models.finding import Finding
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import ScanError, ScanFinding, ScanReport
from .owasp import ASI06_REF
from .scan.mask import mask_snippet, safe_evidence
from .telemetry import (
    ATTR_FINDING_COUNT,
    ATTR_OPERATION,
    SPAN_SCAN,
    NullTracer,
    Tracer,
    get_logger,
)

_logger = get_logger(__name__)
_MAX_ERROR_IDS = 20
_MAX_ERROR_MESSAGE = 200


@dataclass
class _Plan:
    """How one check splits across the two passes."""

    check: MemoryCheck
    position: int
    stream: list[Detector] = field(default_factory=list)
    corpus: list[Detector] = field(default_factory=list)
    whole_check_in_corpus: bool = False

    @property
    def in_corpus_pass(self) -> bool:
        return self.whole_check_in_corpus or bool(self.corpus)


def _plan(checks: list[MemoryCheck]) -> list[_Plan]:
    plans: list[_Plan] = []
    for position, chk in enumerate(checks):
        plan = _Plan(check=chk, position=position)
        if isinstance(chk, SecurityCheck):
            for detector in chk.detectors:
                (plan.corpus if needs_corpus(detector) else plan.stream).append(detector)
        else:
            plan.whole_check_in_corpus = needs_corpus(chk)
        plans.append(plan)
    return plans


class Evaluator:
    """Run the check list and collect a `ScanReport`.

    Attributes:
        config: Settings for this scan, including `fail_closed`.
        checks: Checks to run, in order, on every record.
        tracer: Receives one span per scan. A missing tracer is replaced
            with `NullTracer`, which records nothing.
        index: Nearest-neighbour implementation for corpus detectors.
            `None` uses the exact search in `mimvo.corpus`.
    """

    def __init__(
        self,
        *,
        config: Config,
        checks: list[MemoryCheck],
        tracer: Tracer | None = None,
        index: NeighbourIndex | None = None,
    ) -> None:
        """Store the settings, checks, and tracer used by `scan`.

        Args:
            config: Settings for this scan.
            checks: Checks to run on every record, in this order.
            tracer: Span destination. `None` means record nothing.
            index: Nearest-neighbour implementation. `None` uses exact search.
        """
        self.config = config
        self.checks = checks
        self.tracer: Tracer = tracer or NullTracer()
        self.index = index

    def scan(self, records: Iterable[MemoryRecord], *, query: str | None = None) -> ScanReport:
        """Audit stored records for poisoned facts, hidden instructions, and secrets.

        Args:
            records: Memories to scan. Read once, as a stream; only a packed
                copy of each record is kept for the corpus pass.
            query: The retrieval question for this batch. Passed through as
                `context.query`. A store scan has none; probe-query
                detectors generate one when they need it.

        Returns:
            A `ScanReport`. `total` is how many records were read. `findings`
            lists each problem, highest severity first, then in record and
            check order. Secret text in snippets is masked. `errors` lists
            checks and detectors that failed.
        """
        now = datetime.now(UTC)
        corpus = Corpus(index=self.index)
        ctx = CheckContext(
            config=self.config,
            now=now,
            operation="scan",
            existing=corpus.records(),
            query=query,
            corpus=corpus,
        )
        plans = _plan(self.checks)
        report = ScanReport(generated_at=now, checks=_check_inventory(self.checks))
        started = time.perf_counter()
        # (row, check position, finding)
        rows: list[tuple[int, int, Finding]] = []
        pending: dict[tuple[int, int], dict[str, list[Detection]]] = {}
        with self.tracer.span(SPAN_SCAN, {ATTR_OPERATION: "scan"}) as span:
            for record in records:
                row = corpus.add(record)
                candidate = _candidate(record)
                for plan in plans:
                    if plan.whole_check_in_corpus:
                        continue
                    if isinstance(plan.check, SecurityCheck):
                        by_code = _collect(plan.check, candidate, ctx, plan.stream)
                        if plan.corpus:
                            if by_code:
                                pending[(row, plan.position)] = by_code
                        else:
                            found = _decide(plan.check, by_code, candidate, ctx)
                            rows.extend((row, plan.position, f) for f in found)
                    else:
                        found = _run(plan.check, candidate, ctx)
                        rows.extend((row, plan.position, f) for f in found)
            report.total = len(corpus)

            corpus_plans = [plan for plan in plans if plan.in_corpus_pass]
            if corpus_plans:
                for row in range(len(corpus)):
                    candidate = corpus.candidate(row)
                    for plan in corpus_plans:
                        if isinstance(plan.check, SecurityCheck):
                            by_code = pending.pop((row, plan.position), {})
                            more = _collect(plan.check, candidate, ctx, plan.corpus)
                            for code, detections in more.items():
                                by_code.setdefault(code, []).extend(detections)
                            found = _decide(plan.check, by_code, candidate, ctx)
                        else:
                            found = _run(plan.check, candidate, ctx)
                        rows.extend((row, plan.position, f) for f in found)

            rows.sort(key=lambda item: (-item[2].severity.rank, item[0], item[1]))
            snippets: dict[int, str] = {}
            for row, _, finding in rows:
                if row not in snippets:
                    snippets[row] = mask_snippet(corpus.contents[row])
                report.findings.append(_scan_finding(corpus.ids[row], snippets[row], finding))
            report.errors, report.records_with_errors = _errors(ctx.failures)
            report.duration_seconds = round(time.perf_counter() - started, 4)
            span.set_attribute("mimvo.scanned", report.total)
            span.set_attribute("mimvo.flagged", report.flagged)
            span.set_attribute("mimvo.errors", report.records_with_errors)
            span.set_attribute(ATTR_FINDING_COUNT, len(report.findings))
        return report


def _collect(
    chk: SecurityCheck,
    candidate: MemoryCandidate,
    ctx: CheckContext,
    detectors: list[Detector],
) -> dict[str, list[Detection]]:
    """Run some of a security check's detectors; a crash becomes a failure."""
    if not detectors:
        return {}
    try:
        return chk.collect(candidate, ctx, detectors)
    except Exception as exc:
        _fail(chk, candidate, ctx, exc)
        return {}


def _decide(
    chk: SecurityCheck,
    by_code: dict[str, list[Detection]],
    candidate: MemoryCandidate,
    ctx: CheckContext,
) -> list[Finding]:
    if not by_code:
        return []
    try:
        return chk.decide(by_code)
    except Exception as exc:
        _fail(chk, candidate, ctx, exc)
        return []


def _run(chk: MemoryCheck, candidate: MemoryCandidate, ctx: CheckContext) -> list[Finding]:
    """Run a plain `MemoryCheck`; a crash becomes a failure, not a finding."""
    try:
        found = chk.check(candidate, ctx)
    except Exception as exc:
        _fail(chk, candidate, ctx, exc)
        return []
    name = getattr(chk, "name", None)
    return [
        f.model_copy(update={"check": name}) if f.check is None and isinstance(name, str) else f
        for f in found
    ]


def _fail(chk: MemoryCheck, candidate: MemoryCandidate, ctx: CheckContext, exc: Exception) -> None:
    name = str(getattr(chk, "name", type(chk).__name__))
    _logger.warning("check {!r} raised {}", name, type(exc).__name__)
    ctx.record_failure(check=name, detector=None, error=exc, record_id=candidate.id)


def _candidate(record: MemoryRecord) -> MemoryCandidate:
    return MemoryCandidate.model_construct(
        content=record.content,
        metadata=dict(record.metadata),
        id=record.id,
        derived_from=list(record.derived_from),
        created_at=record.created_at,
        embedding=list(record.embedding) if record.embedding is not None else None,
    )


def _scan_finding(record_id: str, snippet: str, finding: Finding) -> ScanFinding:
    return ScanFinding(
        id=record_id,
        type=finding.code,
        severity=finding.severity,
        detectors=_detectors(finding),
        snippet=snippet,
        action=_report_action(finding.recommended_action, finding.severity),
        owasp=finding.owasp or ASI06_REF,
        message=finding.message,
        check=finding.check or "",
        evidence=safe_evidence(finding.evidence),
        confidence=finding.confidence,
    )


def _errors(failures: list[CheckFailure]) -> tuple[list[ScanError], int]:
    """Group failures by check, detector, and exception type.

    Returns:
        The grouped errors, most records first, and how many distinct
        records had at least one failure.
    """
    groups: dict[tuple[str, str | None, str], ScanError] = {}
    affected: set[str] = set()
    anonymous = 0
    for failure in failures:
        key = (failure.check, failure.detector, failure.error_type)
        error = groups.get(key)
        if error is None:
            error = ScanError(
                check=failure.check,
                detector=failure.detector,
                error_type=failure.error_type,
                message=mask_snippet(failure.message, width=_MAX_ERROR_MESSAGE),
            )
            groups[key] = error
        error.records += 1
        if failure.record_id is None:
            anonymous += 1
        else:
            affected.add(failure.record_id)
            if len(error.record_ids) < _MAX_ERROR_IDS and failure.record_id not in error.record_ids:
                error.record_ids.append(failure.record_id)
    ordered = sorted(groups.values(), key=lambda e: (-e.records, e.check, e.detector or ""))
    return ordered, len(affected) + anonymous


def _check_inventory(checks: list[MemoryCheck]) -> dict[str, list[str]]:
    """Name each check and the detectors it runs, for the report header.

    Args:
        checks: The checks this engine will run.

    Returns:
        `{check name: [detector names]}`. A check without detectors (a
        plain `MemoryCheck`) maps to an empty list.
    """
    inventory: dict[str, list[str]] = {}
    for chk in checks:
        detectors = getattr(chk, "detectors", None) or []
        inventory[str(getattr(chk, "name", type(chk).__name__))] = [
            str(getattr(d, "name", type(d).__name__)) for d in detectors
        ]
    return inventory


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
