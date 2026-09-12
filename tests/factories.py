"""Builders shared across tests (kept out of conftest to import cleanly)."""

from __future__ import annotations

from datetime import datetime

from memtrust import MemoryCandidate, MemoryRecord, Scope, Source
from memtrust._time import utcnow
from memtrust.config import Config
from memtrust.context import CheckContext
from memtrust.semantic.heuristic import HeuristicSemanticAnalyzer


def make_candidate(
    content: str = "hello",
    *,
    trust: str = "user",
    source_type: str = "conversation",
    tenant: str = "acme",
    user: str | None = None,
    namespace: str | None = None,
    authority: float | None = None,
    excerpt: str | None = None,
    **fields: object,
) -> MemoryCandidate:
    return MemoryCandidate(
        content=content,
        source=Source(type=source_type, trust=trust, excerpt=excerpt),
        scope=Scope(tenant_id=tenant, user_id=user, namespace=namespace),
        authority=authority,
        **fields,
    )


def make_record(
    content: str = "hello",
    *,
    id: str = "mem_x",
    trust: str = "user",
    tenant: str = "acme",
    user: str | None = None,
    namespace: str | None = None,
    authority: float = 0.3,
    status: str = "active",
    **fields: object,
) -> MemoryRecord:
    return MemoryRecord(
        id=id,
        content=content,
        source=Source(type="conversation", trust=trust),
        scope=Scope(tenant_id=tenant, user_id=user, namespace=namespace),
        authority=authority,
        trust=trust,
        status=status,
        **fields,
    )


def make_context(
    *,
    scope: Scope | None = None,
    existing: list[MemoryRecord] | None = None,
    config: Config | None = None,
    now_value: datetime | None = None,
) -> CheckContext:
    return CheckContext(
        request_scope=scope or Scope(tenant_id="acme"),
        config=config or Config(),
        semantic=HeuristicSemanticAnalyzer(),
        now=now_value or utcnow(),
        operation="write",
        existing=existing or [],
    )
