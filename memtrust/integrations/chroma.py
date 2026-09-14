"""Chroma vector-store adapter.

Wraps a Chroma ``Collection`` so ingested RAG chunks and long-term memories
are gated by MemTrust. Documents are stored by id and reconstructed on query.

Install with ``pip install "memtrust[chroma]"``.
"""

from __future__ import annotations

from typing import Any

from ..exceptions import BackendError
from ..models.memory import MemoryRecord


class ChromaBackend:
    """Adapter from a Chroma collection to the MemTrust backend protocol.

    Chroma embeds documents with its collection embedding function, so this
    adapter does not take a separate embedder.
    """

    def __init__(self, collection: Any) -> None:
        if not (hasattr(collection, "add") and hasattr(collection, "query")):
            raise BackendError("Chroma collection must provide .add() and .query().")
        self._collection = collection

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        try:
            self._collection.add(
                ids=[memory.id],
                documents=[memory.content],
            )
        except Exception as exc:
            raise BackendError(f"Chroma add failed: {exc}") from exc
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        try:
            res = self._collection.query(query_texts=[query or ""], n_results=max(limit, 1))
        except Exception as exc:
            raise BackendError(f"Chroma query failed: {exc}") from exc
        return _from_query(res)

    def get(self, memory_id: str) -> MemoryRecord | None:
        getter = getattr(self._collection, "get", None)
        if not callable(getter):
            return None
        try:
            res = getter(ids=[memory_id])
        except Exception:
            return None
        records = _from_get(res)
        return records[0] if records else None

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._collection, "delete", None)
        if callable(deleter):
            deleter(ids=[memory_id])


def _column(res: Any, key: str) -> list[Any]:
    if not isinstance(res, dict):
        return []
    value = res.get(key) or []
    if isinstance(value, list) and value and isinstance(value[0], list):
        return list(value[0])
    return list(value) if isinstance(value, list) else []


def _from_query(res: Any) -> list[MemoryRecord]:
    ids = [str(i) for i in _column(res, "ids")]
    docs = [str(d) if d is not None else "" for d in _column(res, "documents")]
    records: list[MemoryRecord] = []
    for i, memory_id in enumerate(ids):
        content = docs[i] if i < len(docs) else ""
        records.append(MemoryRecord(id=memory_id, content=content))
    return records


def _from_get(res: Any) -> list[MemoryRecord]:
    if not isinstance(res, dict):
        return []
    ids = [str(i) for i in (res.get("ids") or [])]
    docs = [str(d) if d is not None else "" for d in (res.get("documents") or [])]
    records: list[MemoryRecord] = []
    for i, memory_id in enumerate(ids):
        content = docs[i] if i < len(docs) else ""
        records.append(MemoryRecord(id=memory_id, content=content))
    return records


__all__ = ["ChromaBackend"]
