"""LangChain vector-store adapter.

Wraps a LangChain ``VectorStore`` so RAG ``add_texts`` / ``similarity_search``
go through MemTrust. Documents are stored by id with MemTrust's record state
in their metadata, so read enforcement survives a round trip.

Install with ``pip install "memtrust[langchain]"``.
"""

from __future__ import annotations

from typing import Any

from ..exceptions import BackendError
from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ._codec import decode_record, state_metadata


class LangChainVectorStoreBackend:
    """Adapter from a LangChain VectorStore to the MemTrust backend protocol.

    ``get`` uses ``get_by_ids`` when the store implements it; otherwise it
    returns ``None``. ``delete`` is a no-op when the store cannot delete by id.
    ``set_status`` replaces the document (delete, then re-add under the same
    id), since LangChain has no portable metadata update.
    """

    def __init__(self, vectorstore: Any) -> None:
        if not (hasattr(vectorstore, "add_texts") and hasattr(vectorstore, "similarity_search")):
            raise BackendError(
                "LangChain vector store must provide .add_texts() and .similarity_search()."
            )
        self._store = vectorstore

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        try:
            self._store.add_texts(
                [memory.content],
                metadatas=[state_metadata(memory)],
                ids=[memory.id],
            )
        except Exception as exc:
            raise BackendError(f"LangChain add_texts failed: {exc}") from exc
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        try:
            docs = self._store.similarity_search(query or "", k=limit)
        except Exception as exc:
            raise BackendError(f"LangChain similarity_search failed: {exc}") from exc
        return [_from_doc(doc) for doc in docs or []]

    def get(self, memory_id: str) -> MemoryRecord | None:
        getter = getattr(self._store, "get_by_ids", None)
        if not callable(getter):
            return None
        try:
            docs = getter([memory_id])
        except Exception:
            return None
        if not docs:
            return None
        return _from_doc(docs[0])

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._store, "delete", None)
        if callable(deleter):
            deleter([memory_id])

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self.get(memory_id)
        if record is None:
            return
        self.delete(memory_id)
        self.add(record.model_copy(update={"status": status}))


def _from_doc(doc: Any) -> MemoryRecord:
    if isinstance(doc, dict):
        content = str(doc.get("page_content") or doc.get("content") or "")
        metadata = doc.get("metadata") or {}
        memory_id = str(doc.get("id") or metadata.get("id") or "lc_unknown")
    else:
        content = str(getattr(doc, "page_content", None) or getattr(doc, "content", "") or "")
        metadata = getattr(doc, "metadata", None) or {}
        memory_id = str(
            getattr(doc, "id", None)
            or (metadata.get("id") if isinstance(metadata, dict) else None)
            or "lc_unknown"
        )
    return decode_record(metadata, id=memory_id, content=content)


__all__ = ["LangChainVectorStoreBackend"]
