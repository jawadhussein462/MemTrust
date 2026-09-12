"""Backend abstraction (Adapter pattern via ``typing.Protocol``).

MemTrust does not own memory storage. Any object that implements this small
Protocol can be protected. Sync and async variants are both first-class; a
method never sometimes-returns-a-coroutine.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ..models.scope import Scope


@runtime_checkable
class MemoryBackend(Protocol):
    """Synchronous memory backend."""

    def add(self, memory: MemoryRecord) -> MemoryRecord: ...

    def search(self, query: str, *, scope: Scope, limit: int = 10) -> list[MemoryRecord]: ...

    def get(self, memory_id: str) -> MemoryRecord | None: ...

    def delete(self, memory_id: str) -> None: ...


@runtime_checkable
class AsyncMemoryBackend(Protocol):
    """Asynchronous memory backend."""

    async def add(self, memory: MemoryRecord) -> MemoryRecord: ...

    async def search(self, query: str, *, scope: Scope, limit: int = 10) -> list[MemoryRecord]: ...

    async def get(self, memory_id: str) -> MemoryRecord | None: ...

    async def delete(self, memory_id: str) -> None: ...


@runtime_checkable
class SupportsSetStatus(Protocol):
    """Optional capability: update a record's lifecycle status in place."""

    def set_status(self, memory_id: str, status: MemoryStatus) -> None: ...


__all__ = [
    "AsyncMemoryBackend",
    "MemoryBackend",
    "SupportsSetStatus",
]
