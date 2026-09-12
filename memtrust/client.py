"""The public facade: :class:`MemTrust` and :class:`AsyncMemTrust`.

``MemTrust`` is the one object most users import. It wires together sensible
defaults (heuristic analyzer, in-memory audit, the standard check pipeline)
so that ``MemTrust()`` just works, while every collaborator can be injected
for advanced use. Sync and async are separate classes; a method is never
sometimes-async.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ._coerce import coerce_candidate, coerce_records, coerce_scope
from .audit.base import AuditStore
from .audit.memory import InMemoryAuditStore
from .backends.base import AsyncMemoryBackend, MemoryBackend
from .checks.base import MemoryCheck, normalize_check
from .clock import Clock, SystemClock
from .config import Config
from .engine import Evaluator
from .exceptions import BackendError, ConfigurationError
from .models.decision import Decision
from .models.enums import Action, AuditEventType, MemoryStatus, Mode
from .models.memory import MemoryCandidate, MemoryRecord
from .models.policy import Policy
from .models.results import AddResult, ReadResult, RevocationReport, SafeMemory
from .models.scope import Scope
from .models.source import Source
from .policies.base import PolicyCallable
from .policies.builtin import builtin_policies
from .policies.engine import PolicyEngine
from .semantic.base import SemanticAnalyzer
from .semantic.heuristic import HeuristicSemanticAnalyzer
from .telemetry import Tracer
from .checks import default_checks


class _ClientBase:
    """Shared construction and pure logic for the sync/async clients."""

    def __init__(
        self,
        *,
        mode: Mode | str | None = None,
        fail_closed: bool | None = None,
        checks: Sequence[Any] | None = None,
        policies: Sequence[Policy | PolicyCallable] | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        audit_store: AuditStore | None = None,
        config: Config | None = None,
        clock: Clock | None = None,
        tracer: Tracer | None = None,
        use_default_checks: bool = True,
    ) -> None:
        base_config = config or Config()
        updates: dict[str, Any] = {}
        if mode is not None:
            updates["mode"] = mode if isinstance(mode, Mode) else Mode(mode)
        if fail_closed is not None:
            updates["fail_closed"] = fail_closed
        self.config: Config = base_config.model_copy(update=updates) if updates else base_config

        # Use ``is None`` (not ``or``): an empty audit store is falsy via __len__.
        self.audit_store: AuditStore = (
            audit_store if audit_store is not None else InMemoryAuditStore()
        )
        semantic: SemanticAnalyzer = (
            semantic_analyzer if semantic_analyzer is not None else HeuristicSemanticAnalyzer()
        )
        resolved_clock: Clock = clock if clock is not None else SystemClock()

        resolved_checks: list[MemoryCheck] = list(default_checks()) if use_default_checks else []
        for chk in checks or []:
            resolved_checks.append(normalize_check(chk))

        declarative: list[Policy] = list(builtin_policies())
        callables: list[PolicyCallable] = []
        for pol in policies or []:
            if isinstance(pol, Policy):
                declarative.append(pol)
            elif callable(pol):
                callables.append(pol)
            else:  # pragma: no cover - defensive
                raise ConfigurationError(f"Not a policy or callable: {pol!r}")

        self._evaluator = Evaluator(
            config=self.config,
            checks=resolved_checks,
            policy_engine=PolicyEngine(declarative, callables),
            semantic=semantic,
            audit=self.audit_store,
            clock=resolved_clock,
            tracer=tracer,
        )
        # Lightweight index of records this guard has written (for revocation).
        self._index: dict[str, MemoryRecord] = {}

    # -- pure evaluation (no backend I/O) --------------------------------------

    def _write_decision(
        self,
        content: str | MemoryCandidate | dict,
        source: Any,
        scope: Any,
        existing: list[MemoryRecord] | None,
    ) -> tuple[MemoryCandidate, Decision]:
        candidate, request_scope = coerce_candidate(
            content, source=source, scope=scope, config=self.config
        )
        decision = self._evaluator.evaluate_write(
            candidate, request_scope=request_scope, existing=existing
        )
        return candidate, decision

    def _read_result(self, records: list, scope: Any) -> ReadResult:
        request_scope = coerce_scope(scope)
        return self._evaluator.evaluate_read(
            coerce_records(records), request_scope=request_scope
        )

    def _register(self, record: MemoryRecord) -> None:
        self._index[record.id] = record

    # -- revocation core (shared) ----------------------------------------------

    def _revoke_core(
        self, source_id: str, pool: dict[str, MemoryRecord]
    ) -> tuple[RevocationReport, set[str]]:
        direct: set[str] = set()
        for rid, rec in pool.items():
            if (
                source_id in rec.provenance.source_ids
                or rec.source.id == source_id
                or source_id in rec.derived_from
            ):
                direct.add(rid)

        revoked = set(direct)
        changed = True
        while changed:
            changed = False
            for rid, rec in pool.items():
                if rid in revoked:
                    continue
                parents = set(rec.derived_from) | set(rec.provenance.derived_from)
                if parents & revoked:
                    revoked.add(rid)
                    changed = True

        for rid in revoked:
            rec = pool.get(rid)
            if rid in self._index:
                self._index[rid] = self._index[rid].model_copy(update={"status": MemoryStatus.REVOKED})
            self._evaluator.log_event(
                AuditEventType.MEMORY_REVOKED,
                scope=rec.scope if rec else None,
                memory_id=rid,
                source_id=source_id,
            )

        affected: set[str] = set()
        for rid in revoked:
            for event in self.audit_store.list(type=AuditEventType.READ_ALLOWED, memory_id=rid):
                if event.agent_id:
                    affected.add(event.agent_id)

        self._evaluator.log_event(AuditEventType.SOURCE_REVOKED, source_id=source_id)

        report = RevocationReport(
            source_id=source_id,
            revoked_memories=sorted(revoked),
            directly_revoked=sorted(direct),
            transitively_revoked=sorted(revoked - direct),
            affected_agents=sorted(affected),
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
        decision = guard.check_write("...", source={...}, scope={...})
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
        source: Source | dict | None = None,
        scope: Scope | dict | None = None,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        """Evaluate whether a memory should be written."""
        _, decision = self._write_decision(content, source, scope, existing)
        return decision

    def check_read(
        self, records: list, *, scope: Scope | dict | None = None
    ) -> ReadResult:
        """Filter records down to those safe to return for ``scope``."""
        return self._read_result(records, scope)

    def protect(self, backend: MemoryBackend) -> ProtectedMemory:
        """Wrap a memory backend so reads/writes are checked automatically."""
        protected = ProtectedMemory(self, backend)
        self._protected.append(protected)
        return protected

    def revoke_source(
        self, source_id: str, *, records: list | None = None
    ) -> RevocationReport:
        """Revoke memories derived from a compromised source; return an impact report."""
        pool = self._revocation_pool(records)
        report, revoked = self._revoke_core(source_id, pool)
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
        source: Source | dict | None = None,
        scope: Scope | dict | None = None,
        existing: list[MemoryRecord] | None = None,
    ) -> Decision:
        _, decision = self._write_decision(content, source, scope, existing)
        return decision

    async def check_read(
        self, records: list, *, scope: Scope | dict | None = None
    ) -> ReadResult:
        return self._read_result(records, scope)

    def protect(self, backend: AsyncMemoryBackend) -> AsyncProtectedMemory:
        protected = AsyncProtectedMemory(self, backend)
        self._protected.append(protected)
        return protected

    async def revoke_source(
        self, source_id: str, *, records: list | None = None
    ) -> RevocationReport:
        pool = self._revocation_pool(records)
        report, revoked = self._revoke_core(source_id, pool)
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

    def add(
        self,
        content: str | MemoryCandidate | dict,
        *,
        source: Source | dict | None = None,
        scope: Scope | dict | None = None,
    ) -> AddResult:
        candidate, _ = coerce_candidate(
            content, source=source, scope=scope, config=self._config
        )
        neighbors = self._neighbors(candidate)
        decision = self._evaluator.evaluate_write(
            candidate, request_scope=candidate.scope, existing=neighbors
        )
        return self._apply_write(candidate, decision)

    def search(
        self, query: str, *, scope: Scope | dict | None = None, limit: int = 10
    ) -> list[SafeMemory]:
        request_scope = coerce_scope(scope)
        try:
            raw = self._backend.search(query, scope=request_scope, limit=limit)
        except Exception as exc:  # noqa: BLE001
            raise BackendError(str(exc)) from exc
        return self._evaluator.evaluate_read(raw, request_scope=request_scope).results

    def get(self, memory_id: str, *, scope: Scope | dict) -> SafeMemory | None:
        """Fetch a record by id, subject to read enforcement.

        ``scope`` is required: a scopeless fetch would bypass tenant/user
        isolation and status/expiry filtering.
        """
        record = self._backend.get(memory_id)
        if record is None:
            return None
        result = self._evaluator.evaluate_read([record], request_scope=coerce_scope(scope))
        return result.results[0] if result.results else None

    def delete(self, memory_id: str) -> None:
        self._backend.delete(memory_id)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        setter = getattr(self._backend, "set_status", None)
        if callable(setter):
            setter(memory_id, status)
            return
        record = self._backend.get(memory_id)
        if record is not None:
            self._backend.add(record.model_copy(update={"status": status}))

    def _all_records(self) -> list[MemoryRecord]:
        """Internal: raw records for the revocation index (not a read API)."""
        lister = getattr(self._backend, "all", None)
        return list(lister()) if callable(lister) else []

    # -- internals --------------------------------------------------------------

    def _neighbors(self, candidate: MemoryCandidate) -> list[MemoryRecord]:
        if self._config.semantic_neighbor_limit <= 0:
            return []
        try:
            return self._backend.search(
                candidate.content,
                scope=candidate.scope,
                limit=self._config.semantic_neighbor_limit,
            )
        except Exception:  # noqa: BLE001 - neighbors are advisory
            return []

    def _apply_write(self, candidate: MemoryCandidate, decision: Decision) -> AddResult:
        if decision.allowed:
            content = (
                decision.rewritten_content
                if decision.rewritten_content is not None
                else candidate.content
            )
            for old_id in decision.supersedes:
                self.set_status(old_id, MemoryStatus.SUPERSEDED)
                self._evaluator.log_event(
                    AuditEventType.MEMORY_SUPERSEDED, scope=candidate.scope, memory_id=old_id
                )
            record = candidate.to_record(
                content=content, status=MemoryStatus.ACTIVE, supersedes=decision.supersedes
            )
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

    async def add(
        self,
        content: str | MemoryCandidate | dict,
        *,
        source: Source | dict | None = None,
        scope: Scope | dict | None = None,
    ) -> AddResult:
        candidate, _ = coerce_candidate(
            content, source=source, scope=scope, config=self._config
        )
        neighbors = await self._neighbors(candidate)
        decision = self._evaluator.evaluate_write(
            candidate, request_scope=candidate.scope, existing=neighbors
        )
        return await self._apply_write(candidate, decision)

    async def search(
        self, query: str, *, scope: Scope | dict | None = None, limit: int = 10
    ) -> list[SafeMemory]:
        request_scope = coerce_scope(scope)
        try:
            raw = await self._backend.search(query, scope=request_scope, limit=limit)
        except Exception as exc:  # noqa: BLE001
            raise BackendError(str(exc)) from exc
        return self._evaluator.evaluate_read(raw, request_scope=request_scope).results

    async def get(self, memory_id: str, *, scope: Scope | dict) -> SafeMemory | None:
        """Fetch a record by id, subject to read enforcement (scope required)."""
        record = await self._backend.get(memory_id)
        if record is None:
            return None
        result = self._evaluator.evaluate_read([record], request_scope=coerce_scope(scope))
        return result.results[0] if result.results else None

    async def delete(self, memory_id: str) -> None:
        await self._backend.delete(memory_id)

    async def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        setter = getattr(self._backend, "set_status", None)
        if callable(setter):
            await setter(memory_id, status)
            return
        record = await self._backend.get(memory_id)
        if record is not None:
            await self._backend.add(record.model_copy(update={"status": status}))

    def _all_records(self) -> list[MemoryRecord]:
        """Internal: raw records for the revocation index (not a read API)."""
        lister = getattr(self._backend, "all", None)
        return list(lister()) if callable(lister) else []

    async def _neighbors(self, candidate: MemoryCandidate) -> list[MemoryRecord]:
        if self._config.semantic_neighbor_limit <= 0:
            return []
        try:
            return await self._backend.search(
                candidate.content,
                scope=candidate.scope,
                limit=self._config.semantic_neighbor_limit,
            )
        except Exception:  # noqa: BLE001
            return []

    async def _apply_write(self, candidate: MemoryCandidate, decision: Decision) -> AddResult:
        if decision.allowed:
            content = (
                decision.rewritten_content
                if decision.rewritten_content is not None
                else candidate.content
            )
            for old_id in decision.supersedes:
                await self.set_status(old_id, MemoryStatus.SUPERSEDED)
                self._evaluator.log_event(
                    AuditEventType.MEMORY_SUPERSEDED, scope=candidate.scope, memory_id=old_id
                )
            record = candidate.to_record(
                content=content, status=MemoryStatus.ACTIVE, supersedes=decision.supersedes
            )
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
