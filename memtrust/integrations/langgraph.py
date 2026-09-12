"""LangGraph ``BaseStore`` adapter.

Maps MemTrust records onto LangGraph's namespaced key/value store. Namespaces
are ``(tenant_id, namespace, user_id)`` tuples so tenant/user partitioning is
reflected in the store itself (MemTrust still re-checks on read).

Install with ``pip install "memtrust[langgraph]"``.
"""

from __future__ import annotations

from typing import Any

from ..models.memory import MemoryRecord
from ..models.scope import Scope

_PLACEHOLDER = "_"


def _namespace(tenant_id: str, namespace: str | None, user_id: str | None) -> tuple[str, ...]:
    return (tenant_id, namespace or _PLACEHOLDER, user_id or _PLACEHOLDER)


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
        ns = _namespace(memory.scope.tenant_id, memory.scope.namespace, memory.scope.user_id)
        self._store.put(ns, memory.id, memory.model_dump(mode="json"))
        return memory

    def search(self, query: str, *, scope: Scope, limit: int = 10) -> list[MemoryRecord]:
        prefix: tuple[str, ...] = (scope.tenant_id,)
        items = self._store.search(prefix, query=query or None, limit=limit)
        records: list[MemoryRecord] = []
        for item in items:
            value = _value_of(item)
            if value is not None:
                records.append(MemoryRecord.model_validate(value))
        return records

    def get(self, memory_id: str) -> MemoryRecord | None:
        # BaseStore.get needs a namespace; when only an id is known, locate it.
        for item, value in self._scan():
            if getattr(item, "key", None) == memory_id or (
                isinstance(item, dict) and item.get("key") == memory_id
            ):
                return MemoryRecord.model_validate(value)
        return None

    def delete(self, memory_id: str) -> None:
        for item, _value in self._scan():
            key = getattr(item, "key", None) or (item.get("key") if isinstance(item, dict) else None)
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
