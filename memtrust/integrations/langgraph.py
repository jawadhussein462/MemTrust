"""LangGraph ``BaseStore`` adapter.

Maps MemTrust records onto LangGraph's namespaced key/value store. The full
record is stored as the item value, keyed by the MemTrust id.

Install with ``pip install "memtrust[langgraph]"``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord

_NS: tuple[str, ...] = ("memtrust",)
_PAGE = 500


def _value_of(item: Any) -> dict[str, Any] | None:
    value = getattr(item, "value", None)
    if value is None and isinstance(item, dict):
        value = item.get("value")
    return value if isinstance(value, dict) else None


class LangGraphStoreBackend:
    """Adapter from a LangGraph ``BaseStore`` to the MemTrust backend protocol.

    ``namespace`` defaults to ``("memtrust",)``; use a per-user namespace such
    as ``("memtrust", user_id)`` to keep users' memories apart.
    """

    def __init__(self, store: Any, *, namespace: tuple[str, ...] = _NS) -> None:
        self._store = store
        self._ns = tuple(namespace)

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        self._store.put(self._ns, memory.id, memory.model_dump(mode="json"))
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        items = self._store.search(self._ns, query=query or None, limit=limit)
        return [MemoryRecord.model_validate(v) for v in map(_value_of, items) if v is not None]

    def get(self, memory_id: str) -> MemoryRecord | None:
        value = _value_of(self._store.get(self._ns, memory_id))
        return MemoryRecord.model_validate(value) if value is not None else None

    def delete(self, memory_id: str) -> None:
        self._store.delete(self._ns, memory_id)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self.get(memory_id)
        if record is not None:
            self.add(record.model_copy(update={"status": status}))

    def all(self) -> Iterator[MemoryRecord]:
        """Every record under this adapter's namespace, paged."""
        offset = 0
        while True:
            items = list(self._store.search(self._ns, query=None, limit=_PAGE, offset=offset))
            for value in map(_value_of, items):
                if value is not None:
                    yield MemoryRecord.model_validate(value)
            if len(items) < _PAGE:
                return
            offset += _PAGE


__all__ = ["LangGraphStoreBackend"]
