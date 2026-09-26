"""The public facade: :class:`MemTrust` and :class:`AsyncMemTrust`.

``MemTrust`` is the one object most users import. It wires together the
standard check pipeline so that ``MemTrust()`` just works, while every
collaborator can be injected for advanced use. Sync and async are separate
classes; a method is never sometimes-async.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ._coerce import coerce_candidate, coerce_records
from .backends.base import AsyncMemoryBackend, MemoryBackend
from .checks import default_checks
from .checks.base import MemoryCheck, normalize_check
from .config import Config
from .engine import Evaluator
from .exceptions import BackendError
from .models.decision import Decision
from .models.enums import Action, MemoryStatus
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import AddResult, ReadResult, RevocationReport, SafeMemory
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

        resolved_checks: list[MemoryCheck] = list(default_checks()) if use_default_checks else []
        for chk in checks or []:
            resolved_checks.append(normalize_check(chk))

        self._evaluator = Evaluator(
            config=self.config,
            checks=resolved_checks,
            tracer=tracer,
        )
        # Lightweight index of records this guard has written (for revocation).
        self._index: dict[str, MemoryRecord] = {}

    # -- pure evaluation (no backend I/O) --------------------------------------

    def _write_decision(
        self,
        content: str | MemoryCandidate | dict,
        existing: list[MemoryRecord] | None,
    ) -> tuple[MemoryCandidate, Decision]:
        candidate = coerce_candidate(content)
        decision = self._evaluator.evaluate_write(candidate, existing=existing)
        return candidate, decision

    def _read_result(self, records: list) -> ReadResult:
        return self._evaluator.evaluate_read(coerce_records(records))

    def _register(self, record: MemoryRecord) -> None:
        self._index[record.id] = record

    # -- revocation core (shared) ----------------------------------------------

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
        pool = dict(self._index)
        for protected in getattr(self, "_protected", []):
            for rec in protected._all_records():
                pool.setdefault(rec.id, rec)
        return pool


class MemTrust(_ClientBase):
    """Synchronous entry point.

    Example::

        guard = MemTrust()
        decision = guard.check_write("...")
        if not decision.allowed:
            print(decision.reason)
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._protected: list[ProtectedMemory] = []

    def check_write(
        self,
        content: str | MemoryCandidate | dict,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        """Evaluate whether a memory should be written."""
        _, decision = self._write_decision(content, existing)
        return decision

    def check_read(self, records: list) -> ReadResult:
        """Filter records down to those safe to return."""
        return self._read_result(records)

    def protect(self, backend: MemoryBackend) -> ProtectedMemory:
        """Wrap a memory backend so reads/writes are checked automatically."""
        protected = ProtectedMemory(self, backend)
        self._protected.append(protected)
        return protected

    def revoke(self, memory_id: str, *, records: list | None = None) -> RevocationReport:
        """Revoke a memory and anything derived from it; return an impact report."""
        pool = self._revocation_pool(records)
        report, revoked = self._revoke_core(memory_id, pool)
        for protected in self._protected:
            for rid in revoked:
                protected.set_status(rid, MemoryStatus.REVOKED)
        return report


class AsyncMemTrust(_ClientBase):
    """Asynchronous entry point. Mirrors :class:`MemTrust`."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._protected: list[AsyncProtectedMemory] = []

    async def check_write(
        self,
        content: str | MemoryCandidate | dict,
        *,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        _, decision = self._write_decision(content, existing)
        return decision

    async def check_read(self, records: list) -> ReadResult:
        return self._read_result(records)

    def protect(self, backend: AsyncMemoryBackend) -> AsyncProtectedMemory:
        protected = AsyncProtectedMemory(self, backend)
        self._protected.append(protected)
        return protected

    async def revoke(self, memory_id: str, *, records: list | None = None) -> RevocationReport:
        pool = self._revocation_pool(records)
        report, revoked = self._revoke_core(memory_id, pool)
        for protected in self._protected:
            for rid in revoked:
                await protected.set_status(rid, MemoryStatus.REVOKED)
        return report


class ProtectedMemory:
    """A memory backend with MemTrust checks applied to every read and write."""

    def __init__(self, guard: MemTrust, backend: MemoryBackend) -> None:
        self._guard = guard
        self._backend = backend
        self._evaluator = guard._evaluator
        self._config = guard.config

    def add(self, content: str | MemoryCandidate | dict) -> AddResult:
        candidate = coerce_candidate(content)
        neighbors = self._neighbors(candidate)
        decision = self._evaluator.evaluate_write(candidate, existing=neighbors)
        return self._apply_write(candidate, decision)

    def search(self, query: str, *, limit: int = 10) -> list[SafeMemory]:
        try:
            raw = self._backend.search(query, limit=limit)
        except Exception as exc:
            raise BackendError(str(exc)) from exc
        return self._evaluator.evaluate_read(raw).results

    def get(self, memory_id: str) -> SafeMemory | None:
        """Fetch a record by id, subject to read enforcement."""
        record = self._backend.get(memory_id)
        if record is None:
            return None
        result = self._evaluator.evaluate_read([record])
        return result.results[0] if result.results else None

    def delete(self, memory_id: str) -> None:
        self._backend.delete(memory_id)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        setter = getattr(self._backend, "set_status", None)
        if callable(setter):
            setter(memory_id, status)
            return
        record = self._backend.get(memory_id)
        if record is None:
            return
        stored = self._backend.add(record.model_copy(update={"status": status}))
        if stored.id != memory_id:
            # The backend assigned a new id instead of upserting: drop the old
            # copy so it cannot keep surfacing with its previous status.
            self._backend.delete(memory_id)

    def _all_records(self) -> list[MemoryRecord]:
        """Internal: raw records for the revocation index (not a read API)."""
        lister = getattr(self._backend, "all", None)
        return list(lister()) if callable(lister) else []

    # -- internals --------------------------------------------------------------

    def _neighbors(self, candidate: MemoryCandidate) -> list[MemoryRecord]:
        if self._config.neighbor_limit <= 0:
            return []
        try:
            return self._backend.search(
                candidate.content,
                limit=self._config.neighbor_limit,
            )
        except Exception:
            return []

    def _apply_write(self, candidate: MemoryCandidate, decision: Decision) -> AddResult:
        if decision.allowed:
            for old_id in decision.supersedes:
                self.set_status(old_id, MemoryStatus.SUPERSEDED)
            record = candidate.to_record(status=MemoryStatus.ACTIVE, supersedes=decision.supersedes)
            stored = self._backend.add(record)
            self._guard._register(stored)
            return AddResult(allowed=True, decision=decision, record=stored)

        if decision.action == Action.QUARANTINE and self._config.store_quarantined:
            record = candidate.to_record(status=MemoryStatus.QUARANTINED)
            stored = self._backend.add(record)
            self._guard._register(stored)
            return AddResult(allowed=False, decision=decision, record=stored)

        if self._config.raise_on_blocked_add:
            raise BackendError(f"Write blocked: {decision.reason}")
        return AddResult(allowed=False, decision=decision, record=None)


class AsyncProtectedMemory:
    """Async counterpart of :class:`ProtectedMemory`."""

    def __init__(self, guard: AsyncMemTrust, backend: AsyncMemoryBackend) -> None:
        self._guard = guard
        self._backend = backend
        self._evaluator = guard._evaluator
        self._config = guard.config

    async def add(self, content: str | MemoryCandidate | dict) -> AddResult:
        candidate = coerce_candidate(content)
        neighbors = await self._neighbors(candidate)
        decision = self._evaluator.evaluate_write(candidate, existing=neighbors)
        return await self._apply_write(candidate, decision)

    async def search(self, query: str, *, limit: int = 10) -> list[SafeMemory]:
        try:
            raw = await self._backend.search(query, limit=limit)
        except Exception as exc:
            raise BackendError(str(exc)) from exc
        return self._evaluator.evaluate_read(raw).results

    async def get(self, memory_id: str) -> SafeMemory | None:
        """Fetch a record by id, subject to read enforcement."""
        record = await self._backend.get(memory_id)
        if record is None:
            return None
        result = self._evaluator.evaluate_read([record])
        return result.results[0] if result.results else None

    async def delete(self, memory_id: str) -> None:
        await self._backend.delete(memory_id)

    async def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        setter = getattr(self._backend, "set_status", None)
        if callable(setter):
            await setter(memory_id, status)
            return
        record = await self._backend.get(memory_id)
        if record is None:
            return
        stored = await self._backend.add(record.model_copy(update={"status": status}))
        if stored.id != memory_id:
            # The backend assigned a new id instead of upserting: drop the old
            # copy so it cannot keep surfacing with its previous status.
            await self._backend.delete(memory_id)

    def _all_records(self) -> list[MemoryRecord]:
        """Internal: raw records for the revocation index (not a read API)."""
        lister = getattr(self._backend, "all", None)
        return list(lister()) if callable(lister) else []

    async def _neighbors(self, candidate: MemoryCandidate) -> list[MemoryRecord]:
        if self._config.neighbor_limit <= 0:
            return []
        try:
            return await self._backend.search(
                candidate.content,
                limit=self._config.neighbor_limit,
            )
        except Exception:
            return []

    async def _apply_write(self, candidate: MemoryCandidate, decision: Decision) -> AddResult:
        if decision.allowed:
            for old_id in decision.supersedes:
                await self.set_status(old_id, MemoryStatus.SUPERSEDED)
            record = candidate.to_record(status=MemoryStatus.ACTIVE, supersedes=decision.supersedes)
            stored = await self._backend.add(record)
            self._guard._register(stored)
            return AddResult(allowed=True, decision=decision, record=stored)

        if decision.action == Action.QUARANTINE and self._config.store_quarantined:
            record = candidate.to_record(status=MemoryStatus.QUARANTINED)
            stored = await self._backend.add(record)
            self._guard._register(stored)
            return AddResult(allowed=False, decision=decision, record=stored)

        if self._config.raise_on_blocked_add:
            raise BackendError(f"Write blocked: {decision.reason}")
        return AddResult(allowed=False, decision=decision, record=None)


__all__ = [
    "AsyncMemTrust",
    "AsyncProtectedMemory",
    "MemTrust",
    "ProtectedMemory",
]
