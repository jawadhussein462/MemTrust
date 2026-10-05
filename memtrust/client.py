"""The public facade: :class:`MemTrust` and :class:`AsyncMemTrust`.

``MemTrust`` is the one object most users import. It wires the check
pipeline so ``MemTrust().scan(...)`` just works. Sync and async are
separate classes; a method is never sometimes-async.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ._coerce import coerce_candidate, coerce_record, coerce_records
from .backends.base import SupportsListing
from .checks import default_checks
from .checks.base import MemoryCheck, normalize_check
from .config import Config
from .engine import Evaluator
from .exceptions import ConfigurationError
from .models.decision import Decision
from .models.enums import MemoryStatus
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import ReadResult, RevocationReport, ScanReport
from .telemetry import Tracer


class _ClientBase:
    """Shared construction and pure logic for the sync/async clients."""

    def __init__(
        self,
        *,
        fail_closed: bool | None = None,
        checks: Sequence[Any] | None = None,
        config: Config | None = None,
        tracer: Tracer | None = None,
        use_default_checks: bool = True,
    ) -> None:
        base_config = config or Config()
        updates: dict[str, Any] = {}
        if fail_closed is not None:
            updates["fail_closed"] = fail_closed
        self.config: Config = base_config.model_copy(update=updates) if updates else base_config

        # A user check named like a default ("injection", "secrets", ...) replaces
        # it, so a configured ``InjectionCheck(detectors=[...])`` slots into the
        # default pipeline instead of running alongside the heuristic one.
        resolved_checks: list[MemoryCheck] = list(default_checks()) if use_default_checks else []
        for chk in checks or []:
            normalized = normalize_check(chk)
            position = next(
                (
                    i
                    for i, existing in enumerate(resolved_checks)
                    if existing.name == normalized.name
                ),
                None,
            )
            if position is None:
                resolved_checks.append(normalized)
            else:
                resolved_checks[position] = normalized

        self._evaluator = Evaluator(
            config=self.config,
            checks=resolved_checks,
            tracer=tracer,
        )
        self._index: dict[str, MemoryRecord] = {}

    def _write_decision(
        self,
        content: str | MemoryCandidate | dict,
        existing: list[MemoryRecord] | None,
    ) -> tuple[MemoryCandidate, Decision]:
        candidate = coerce_candidate(content)
        decision = self._evaluator.evaluate_write(candidate, existing=existing)
        return candidate, decision

    def _read_result(self, records: list, query: str | None = None) -> ReadResult:
        return self._evaluator.evaluate_read(coerce_records(records), query=query)

    def scan(self, source: SupportsListing | Iterable[Any]) -> ScanReport:
        """Find poisoned facts, hidden instructions, and leaked secrets.

        ``source`` is a backend that can list its records, a scan source, or
        an iterable of records/dicts. Records are streamed, never loaded all
        at once. Nothing is modified.
        """
        records_fn = getattr(source, "records", None)
        if callable(records_fn):
            items: Iterable[Any] = records_fn()
        elif isinstance(source, SupportsListing):
            items = source.all()
        elif isinstance(source, Iterable) and not isinstance(source, str | bytes | dict):
            items = source
        else:
            raise ConfigurationError(
                f"Cannot scan {type(source).__name__}: pass a backend with .all(), "
                "a scan source, or an iterable of records."
            )
        return self._evaluator.scan(coerce_record(item) for item in items)

    def _revoke_core(
        self, memory_id: str, pool: dict[str, MemoryRecord]
    ) -> tuple[RevocationReport, set[str]]:
        direct: set[str] = set()
        if memory_id in pool or memory_id in self._index:
            direct.add(memory_id)

        revoked = set(direct)
        changed = True
        while changed:
            changed = False
            for rid, rec in pool.items():
                if rid in revoked:
                    continue
                parents = set(rec.derived_from)
                if parents & revoked:
                    revoked.add(rid)
                    changed = True

        for rid in revoked:
            if rid in self._index:
                self._index[rid] = self._index[rid].model_copy(
                    update={"status": MemoryStatus.REVOKED}
                )

        report = RevocationReport(
            memory_id=memory_id,
            revoked_memories=sorted(revoked),
            directly_revoked=sorted(direct),
            transitively_revoked=sorted(revoked - direct),
        )
        return report, revoked

    def _revocation_pool(self, records: list | None) -> dict[str, MemoryRecord]:
        if records is not None:
            return {r.id: r for r in coerce_records(records)}
        return dict(self._index)


class MemTrust(_ClientBase):
    """Synchronous entry point.

    Example::

        report = MemTrust().scan(records)
        print(report)
    """

    def check_write(
        self,
        content: str | MemoryCandidate | dict,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        """Evaluate a candidate memory (used by tests and custom check wiring)."""
        _, decision = self._write_decision(content, existing)
        return decision

    def check_read(self, records: list, *, query: str | None = None) -> ReadResult:
        """Filter records down to those the checks would not flag."""
        return self._read_result(records, query)

    def revoke(self, memory_id: str, *, records: list | None = None) -> RevocationReport:
        """Revoke a memory and anything derived from it; return an impact report."""
        pool = self._revocation_pool(records)
        report, _revoked = self._revoke_core(memory_id, pool)
        return report


class AsyncMemTrust(_ClientBase):
    """Asynchronous entry point. Mirrors :class:`MemTrust`."""

    async def check_write(
        self,
        content: str | MemoryCandidate | dict,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        _, decision = self._write_decision(content, existing)
        return decision

    async def check_read(self, records: list, *, query: str | None = None) -> ReadResult:
        return self._read_result(records, query)

    async def scan(self, source: SupportsListing | Iterable[Any]) -> ScanReport:
        return super().scan(source)

    async def revoke(self, memory_id: str, *, records: list | None = None) -> RevocationReport:
        pool = self._revocation_pool(records)
        report, _revoked = self._revoke_core(memory_id, pool)
        return report


__all__ = [
    "AsyncMemTrust",
    "MemTrust",
]
