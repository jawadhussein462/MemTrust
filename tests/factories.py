"""Builders shared across tests (kept out of conftest to import cleanly)."""

from __future__ import annotations

from datetime import datetime

from memtrust import MemoryCandidate, MemoryRecord
from memtrust._time import utcnow
from memtrust.config import Config
from memtrust.context import CheckContext
from memtrust.semantic.heuristic import HeuristicSemanticAnalyzer


def make_candidate(
    content: str = "hello",
    *,
    excerpt: str | None = None,
    **fields: object,
) -> MemoryCandidate:
    return MemoryCandidate(content=content, excerpt=excerpt, **fields)


def make_record(
    content: str = "hello",
    *,
    id: str = "mem_x",
    status: str = "active",
    **fields: object,
) -> MemoryRecord:
    return MemoryRecord(id=id, content=content, status=status, **fields)


def make_context(
    *,
    existing: list[MemoryRecord] | None = None,
    config: Config | None = None,
    now_value: datetime | None = None,
) -> CheckContext:
    return CheckContext(
        config=config or Config(),
        semantic=HeuristicSemanticAnalyzer(),
        now=now_value or utcnow(),
        operation="write",
        existing=existing or [],
    )
