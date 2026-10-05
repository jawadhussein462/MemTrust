"""Backend abstraction (Adapter pattern via ``typing.Protocol``).

MemTrust does not own memory storage. Any object that implements this small
Protocol can be protected. Sync and async variants are both first-class; a
method never sometimes-returns-a-coroutine.

Read enforcement depends on the backend returning each record's MemTrust
state (``status``, ``derived_from``) exactly as it was written. A backend
that stores only the text makes every record come back ``ACTIVE``, so
quarantined and revoked memories would surface again. Backends should also
implement :class:`SupportsSetStatus` to update status in place, and
:class:`SupportsListing` to enable revocation and scanning across the whole
store.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord


@runtime_checkable
class MemoryBackend(Protocol):
    """Synchronous memory backend."""

    def add(self, memory: MemoryRecord) -> MemoryRecord: ...

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]: ...

    def get(self, memory_id: str) -> MemoryRecord | None: ...

    def delete(self, memory_id: str) -> None: ...


@runtime_checkable
class AsyncMemoryBackend(Protocol):
    """Asynchronous memory backend."""

    async def add(self, memory: MemoryRecord) -> MemoryRecord: ...

    async def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]: ...

    async def get(self, memory_id: str) -> MemoryRecord | None: ...

    async def delete(self, memory_id: str) -> None: ...


@runtime_checkable
class SupportsSetStatus(Protocol):
    """Optional capability: update a record's lifecycle status in place."""

    def set_status(self, memory_id: str, status: MemoryStatus) -> None: ...


@runtime_checkable
class SupportsListing(Protocol):
    """Optional capability: iterate every stored record (revocation, scanning)."""

    def all(self) -> Iterable[MemoryRecord]: ...


__all__ = [
    "AsyncMemoryBackend",
    "MemoryBackend",
    "SupportsListing",
    "SupportsSetStatus",
]
