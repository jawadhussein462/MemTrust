"""Chroma vector-store adapter.

Wraps a Chroma ``Collection`` so ingested RAG chunks and long-term memories
are gated by MemTrust. Document text is stored as the Chroma document and
MemTrust's record state (status, validity, lineage) as metadata, so read
enforcement survives a round trip.

Install with ``pip install "memtrust[chroma]"``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..exceptions import BackendError
from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ._codec import decode_record, state_metadata

_PAGE = 500


class ChromaBackend:
    """Adapter from a Chroma collection to the MemTrust backend protocol.

    Chroma embeds documents with its collection embedding function, so this
    adapter does not take a separate embedder. Writes use ``upsert`` so a
    record id always maps to one document.
    """

    def __init__(self, collection: Any) -> None:
        if not (hasattr(collection, "upsert") and hasattr(collection, "query")):
            raise BackendError("Chroma collection must provide .upsert() and .query().")
        self._collection = collection

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        try:
            self._collection.upsert(
                ids=[memory.id],
                documents=[memory.content],
                metadatas=[state_metadata(memory)],
            )
        except Exception as exc:
            raise BackendError(f"Chroma upsert failed: {exc}") from exc
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        try:
            res = self._collection.query(
                query_texts=[query or ""],
                n_results=max(limit, 1),
                include=["documents", "metadatas"],
            )
        except Exception as exc:
            raise BackendError(f"Chroma query failed: {exc}") from exc
        return _records(res, nested=True)

    def get(self, memory_id: str) -> MemoryRecord | None:
        try:
            res = self._collection.get(ids=[memory_id], include=["documents", "metadatas"])
        except Exception:
            return None
        records = _records(res, nested=False)
        return records[0] if records else None

    def delete(self, memory_id: str) -> None:
        self._collection.delete(ids=[memory_id])

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self.get(memory_id)
        if record is None:
            return
        updated = record.model_copy(update={"status": status})
        try:
            self._collection.update(ids=[memory_id], metadatas=[state_metadata(updated)])
        except Exception as exc:
            raise BackendError(f"Chroma update failed: {exc}") from exc

    def all(self) -> Iterator[MemoryRecord]:
        """Every record in the collection, paged."""
        offset = 0
        while True:
            res = self._collection.get(
                limit=_PAGE, offset=offset, include=["documents", "metadatas"]
            )
            page = _records(res, nested=False)
            yield from page
            if len(page) < _PAGE:
                return
            offset += _PAGE


def _column(res: Any, key: str, *, nested: bool) -> list[Any]:
    """Read a result column; ``query`` nests one list per query text."""
    if not isinstance(res, dict):
        return []
    value = res.get(key) or []
    if nested and value and isinstance(value[0], list):
        value = value[0]
    return list(value) if isinstance(value, list) else []


def _records(res: Any, *, nested: bool) -> list[MemoryRecord]:
    ids = [str(i) for i in _column(res, "ids", nested=nested)]
    docs = _column(res, "documents", nested=nested)
    metas = _column(res, "metadatas", nested=nested)
    records: list[MemoryRecord] = []
    for i, memory_id in enumerate(ids):
        doc = docs[i] if i < len(docs) else None
        meta = metas[i] if i < len(metas) else None
        records.append(
            decode_record(meta, id=memory_id, content=str(doc) if doc is not None else "")
        )
    return records


__all__ = ["ChromaBackend"]
