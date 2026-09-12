"""LangGraph ``BaseStore`` adapter.

Maps MemTrust records onto LangGraph's namespaced key/value store.

Install with ``pip install "memtrust[langgraph]"``.
"""

from __future__ import annotations

from typing import Any

from ..models.memory import MemoryRecord

_NS: tuple[str, ...] = ("memtrust",)


def _value_of(item: Any) -> dict[str, Any] | None:
    value = getattr(item, "value", None)
    if value is None and isinstance(item, dict):
        value = item.get("value")
    return value if isinstance(value, dict) else None


def _namespace_of(item: Any) -> tuple[str, ...] | None:
    ns = getattr(item, "namespace", None)
    if ns is None and isinstance(item, dict):
        ns = item.get("namespace")
    return tuple(ns) if ns else None


class LangGraphStoreBackend:
    """Adapter from a LangGraph ``BaseStore`` to the MemTrust backend protocol."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        self._store.put(_NS, memory.id, memory.model_dump(mode="json"))
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        items = self._store.search(_NS, query=query or None, limit=limit)
        records: list[MemoryRecord] = []
        for item in items:
            value = _value_of(item)
            if value is not None:
                records.append(MemoryRecord.model_validate(value))
        return records

    def get(self, memory_id: str) -> MemoryRecord | None:
        for item, value in self._scan():
            if getattr(item, "key", None) == memory_id or (
                isinstance(item, dict) and item.get("key") == memory_id
            ):
                return MemoryRecord.model_validate(value)
        return None

    def delete(self, memory_id: str) -> None:
        for item, _value in self._scan():
            key = getattr(item, "key", None) or (
                item.get("key") if isinstance(item, dict) else None
            )
            if key == memory_id:
                ns = _namespace_of(item)
                if ns is not None:
                    self._store.delete(ns, memory_id)
                return

    def _scan(self, limit: int = 1000) -> list[tuple[Any, dict[str, Any]]]:
        items = self._store.search((), query=None, limit=limit)
        out: list[tuple[Any, dict[str, Any]]] = []
        for item in items:
            value = _value_of(item)
            if value is not None:
                out.append((item, value))
        return out


__all__ = ["LangGraphStoreBackend"]
