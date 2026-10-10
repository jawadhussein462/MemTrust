"""Check a memory before it is written, or filter records at retrieve time."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..client import MemorySec
from ..models.enums import Action, Severity
from ..models.finding import Finding
from ..models.memory import MemoryRecord
from ..models.results import ScanReport


def _strongest_action(findings: Sequence[Finding]) -> Action | None:
    actions = [f.recommended_action for f in findings if f.recommended_action is not None]
    if not actions:
        return None
    return max(actions, key=lambda action: action.precedence)


def _worst_severity(findings: Sequence[Finding]) -> Severity | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda item: item.rank)


@dataclass(frozen=True)
class WriteDecision:
    """Whether a memory may be written, and why.

    Attributes:
        allow: `True` when nothing reached `block_at`.
        findings: Problems found in the candidate text.
        action: Strongest recommended action among the findings, or `None`.
        report: The scan report for this one record.
    """

    allow: bool
    findings: list[Finding]
    action: Action | None
    report: ScanReport


class WriteGuard:
    """Reject a memory before it is stored.

    This is the hook the empty `integrations/` folder was missing. Call
    `inspect` (or `allow`) in the writer's path; the store scanner remains
    the after-the-fact audit.

    Args:
        client: Scanner used for the check. `None` builds `MemorySec()`.
        block_at: Lowest severity that refuses the write. Default `HIGH`.
    """

    def __init__(
        self,
        *,
        client: MemorySec | None = None,
        block_at: Severity = Severity.HIGH,
    ) -> None:
        self.client = client or MemorySec()
        self.block_at = block_at

    def inspect(
        self,
        content: str,
        *,
        metadata: dict[str, object] | None = None,
        memory_id: str = "pending",
    ) -> WriteDecision:
        """Scan one candidate and decide whether it may be written.

        Args:
            content: Text about to be stored.
            metadata: Optional store fields copied onto the record.
            memory_id: Id used in the report. Default `"pending"`.

        Returns:
            A `WriteDecision`. `allow` is `False` when any finding is at
            least `block_at`.
        """
        record = MemoryRecord(id=memory_id, content=content, metadata=metadata or {})
        report = self.client.scan([record])
        findings = [
            Finding(
                code=item.type,
                severity=item.severity,
                message=item.message,
                evidence={"detectors": item.detectors},
                check=item.detectors[0] if item.detectors else None,
                recommended_action=item.action,
                owasp=item.owasp,
            )
            for item in report.findings
        ]
        worst = _worst_severity(findings)
        blocked = worst is not None and worst.is_at_least(self.block_at)
        return WriteDecision(
            allow=not blocked,
            findings=findings,
            action=_strongest_action(findings),
            report=report,
        )

    def allow(self, content: str, **kwargs: object) -> bool:
        """Return whether `content` may be written.

        Args:
            content: Text about to be stored.
            **kwargs: Forwarded to `inspect` (`metadata=`, `memory_id=`).

        Returns:
            `True` when `inspect` would allow the write.
        """
        metadata = kwargs.get("metadata")
        memory_id = kwargs.get("memory_id", "pending")
        meta = metadata if isinstance(metadata, dict) else None
        mid = memory_id if isinstance(memory_id, str) else "pending"
        return self.inspect(content, metadata=meta, memory_id=mid).allow


class RetrieveGuard:
    """Drop retrieved memories that the scanner flags, given a query.

    FilterRAG-style: this runs at inference time, when a query exists. A
    store scan has no query, so this class is not on the CLI path.
    Probe-query detection is the scan-time counterpart.

    Args:
        client: Scanner used on the retrieved batch.
        block_at: Lowest severity that drops a record. Default `HIGH`.
    """

    def __init__(
        self,
        *,
        client: MemorySec | None = None,
        block_at: Severity = Severity.HIGH,
    ) -> None:
        self.client = client or MemorySec()
        self.block_at = block_at

    def filter(
        self,
        records: Sequence[MemoryRecord],
        *,
        query: str,
    ) -> list[MemoryRecord]:
        """Return records that did not reach `block_at`.

        Args:
            records: Memories just retrieved for `query`.
            query: The retrieval question. Passed through to detectors
                that read `context.query`.

        Returns:
            The subset of `records` that the scan did not flag at
            `block_at` or worse. Order is preserved.
        """
        report = self.client.scan(records, query=query)
        blocked = {item.id for item in report.findings if item.severity.is_at_least(self.block_at)}
        return [record for record in records if record.id not in blocked]


__all__ = ["RetrieveGuard", "WriteDecision", "WriteGuard"]
