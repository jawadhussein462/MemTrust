"""Reference in-memory backends (sync + async).

Excellent for local development, examples, and tests.
"""

from __future__ import annotations

from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ..text import similarity


class InMemoryBackend:
    """A dict-backed memory store."""

    def __init__(self) -> None:
        self._store: dict[str, MemoryRecord] = {}

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        # Upsert by id so supersession/status updates are stable.
        self._store[memory.id] = memory
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        candidates = list(self._store.values())
        if query:
            candidates.sort(key=lambda r: similarity(query, r.content), reverse=True)
        else:
            candidates.sort(key=lambda r: r.created_at, reverse=True)
        return candidates[:limit]

    def get(self, memory_id: str) -> MemoryRecord | None:
        return self._store.get(memory_id)

    def delete(self, memory_id: str) -> None:
        self._store.pop(memory_id, None)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self._store.get(memory_id)
        if record is not None:
            self._store[memory_id] = record.model_copy(update={"status": status})

    def all(self) -> list[MemoryRecord]:
        return list(self._store.values())

    def __len__(self) -> int:
        return len(self._store)


class AsyncInMemoryBackend:
    """Async wrapper over :class:`InMemoryBackend` for async code paths."""

    def __init__(self, inner: InMemoryBackend | None = None) -> None:
        self._inner = inner or InMemoryBackend()

    async def add(self, memory: MemoryRecord) -> MemoryRecord:
        return self._inner.add(memory)

    async def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        return self._inner.search(query, limit=limit)

    async def get(self, memory_id: str) -> MemoryRecord | None:
        return self._inner.get(memory_id)

    async def delete(self, memory_id: str) -> None:
        self._inner.delete(memory_id)

    async def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        self._inner.set_status(memory_id, status)

    def all(self) -> list[MemoryRecord]:
        return self._inner.all()


__all__ = ["AsyncInMemoryBackend", "InMemoryBackend"]
