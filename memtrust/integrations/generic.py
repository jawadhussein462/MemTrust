"""Generic adapter for custom backends.

Because :class:`~memtrust.backends.MemoryBackend` is a ``typing.Protocol``,
*any* object with ``add``/``search``/``get``/``delete`` already works with
``MemTrust().protect(...)`` — no base class required. This module adds a
convenience adapter for wrapping loose callables.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models.memory import MemoryRecord
from ..models.scope import Scope

AddFn = Callable[[MemoryRecord], MemoryRecord]
SearchFn = Callable[[str, Scope, int], list[MemoryRecord]]
GetFn = Callable[[str], "MemoryRecord | None"]
DeleteFn = Callable[[str], None]


class FunctionBackend:
    """Wrap plain functions as a :class:`~memtrust.backends.MemoryBackend`."""

    def __init__(
        self,
        *,
        add: AddFn,
        search: SearchFn,
        get: GetFn | None = None,
        delete: DeleteFn | None = None,
    ) -> None:
        self._add = add
        self._search = search
        self._get = get
        self._delete = delete

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        return self._add(memory)

    def search(self, query: str, *, scope: Scope, limit: int = 10) -> list[MemoryRecord]:
        return self._search(query, scope, limit)

    def get(self, memory_id: str) -> MemoryRecord | None:
        return self._get(memory_id) if self._get else None

    def delete(self, memory_id: str) -> None:
        if self._delete:
            self._delete(memory_id)


__all__ = ["FunctionBackend"]
