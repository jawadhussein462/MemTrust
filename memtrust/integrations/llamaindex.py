"""LlamaIndex adapter.

Wraps a LlamaIndex index (typically ``VectorStoreIndex``) so RAG inserts and
retrieves go through MemTrust. Each record is inserted as a ``Document``
whose ``doc_id`` is the MemTrust id; MemTrust's record state travels in the
document metadata (excluded from embedding and LLM text), so read
enforcement survives a round trip.

Install with ``pip install "memtrust[llamaindex]"``.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

from ..exceptions import BackendError
from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ._codec import STATE_KEY, decode_record, state_metadata


class LlamaIndexBackend:
    """Adapter from a LlamaIndex index to the MemTrust backend protocol.

    The index must support ``insert`` and ``as_retriever``. ``get``,
    ``delete``, and ``set_status`` use the index ``docstore`` and
    ``delete_ref_doc`` when present. With an external vector store that
    keeps the text itself, build the index with ``store_nodes_override=True``
    so the docstore still holds nodes; otherwise ``get`` cannot find records
    and status changes (supersede, revoke) cannot be applied.
    """

    def __init__(self, index: Any) -> None:
        if not (hasattr(index, "insert") and hasattr(index, "as_retriever")):
            raise BackendError("LlamaIndex index must provide .insert() and .as_retriever().")
        self._index = index

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        # Replace any previous version so one MemTrust id maps to one document.
        self._delete_ref_doc(memory.id)
        try:
            self._index.insert(_document(memory))
        except Exception as exc:
            raise BackendError(f"LlamaIndex insert failed: {exc}") from exc
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        try:
            retriever = self._index.as_retriever(similarity_top_k=limit)
            hits = retriever.retrieve(query or "")
        except Exception as exc:
            raise BackendError(f"LlamaIndex retrieve failed: {exc}") from exc
        records: list[MemoryRecord] = []
        for hit in hits or []:
            node = getattr(hit, "node", hit)
            records.append(_from_node(node))
        return records

    def get(self, memory_id: str) -> MemoryRecord | None:
        node = self._first_node(memory_id)
        return _from_node(node, memory_id=memory_id) if node is not None else None

    def delete(self, memory_id: str) -> None:
        if not self._delete_ref_doc(memory_id):
            fallback = getattr(self._index, "delete", None)
            if callable(fallback):
                fallback(memory_id)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self.get(memory_id)
        if record is None:
            return
        self.add(record.model_copy(update={"status": status}))

    def all(self) -> Iterator[MemoryRecord]:
        """Every document tracked in ``ref_doc_info``."""
        info = getattr(self._index, "ref_doc_info", None)
        for memory_id in list(info or {}):
            record = self.get(str(memory_id))
            if record is not None:
                yield record

    def _first_node(self, memory_id: str) -> Any:
        docstore = getattr(self._index, "docstore", None)
        get_info = getattr(docstore, "get_ref_doc_info", None)
        info = get_info(memory_id) if callable(get_info) else None
        node_ids = list(getattr(info, "node_ids", None) or [])
        get_node = getattr(docstore, "get_node", None)
        if node_ids and callable(get_node):
            try:
                return get_node(node_ids[0])
            except Exception:
                return None
        get_document = getattr(docstore, "get_document", None)
        if callable(get_document):
            try:
                return get_document(memory_id)
            except Exception:
                return None
        return None

    def _delete_ref_doc(self, memory_id: str) -> bool:
        deleter = getattr(self._index, "delete_ref_doc", None)
        if not callable(deleter):
            return False
        try:
            deleter(memory_id, delete_from_docstore=True)
        except Exception:
            return False
        return True


def _document(memory: MemoryRecord) -> Any:
    metadata = state_metadata(memory)
    try:
        from llama_index.core import Document
    except ImportError:
        return SimpleNamespace(
            text=memory.content, doc_id=memory.id, metadata=metadata, id_=memory.id
        )
    return Document(
        text=memory.content,
        doc_id=memory.id,
        metadata=metadata,
        excluded_embed_metadata_keys=[STATE_KEY],
        excluded_llm_metadata_keys=[STATE_KEY],
    )


def _node_text(node: Any) -> str:
    getter = getattr(node, "get_content", None)
    if callable(getter):
        try:
            return str(getter())
        except TypeError:
            return str(getter)
    for attr in ("text", "page_content"):
        value = getattr(node, attr, None)
        if isinstance(value, str):
            return value
    return str(node)


def _from_node(node: Any, *, memory_id: str | None = None) -> MemoryRecord:
    metadata = getattr(node, "metadata", None) or getattr(node, "extra_info", None) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    fallback_id = (
        memory_id
        or getattr(node, "ref_doc_id", None)
        or getattr(node, "doc_id", None)
        or getattr(node, "id_", None)
        or getattr(node, "node_id", None)
        or "llama_unknown"
    )
    return decode_record(metadata, id=str(fallback_id), content=_node_text(node))


__all__ = ["LlamaIndexBackend"]
