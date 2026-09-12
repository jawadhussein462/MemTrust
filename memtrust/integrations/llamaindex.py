"""LlamaIndex adapter.

Wraps a LlamaIndex index (typically ``VectorStoreIndex``) so RAG inserts and
retrieves go through MemTrust. The full record is stored on node/document
metadata under ``memtrust``.

Install with ``pip install "memtrust[llamaindex]"``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ..exceptions import BackendError
from ..models.memory import MemoryRecord
from ._codec import decode_record, encode_record


class LlamaIndexBackend:
    """Adapter from a LlamaIndex index to the MemTrust backend protocol.

    The index must support ``insert`` and ``as_retriever``. ``get`` / ``delete``
    use ``docstore`` / ``delete_ref_doc`` when present.
    """

    def __init__(self, index: Any) -> None:
        if not (hasattr(index, "insert") and hasattr(index, "as_retriever")):
            raise BackendError("LlamaIndex index must provide .insert() and .as_retriever().")
        self._index = index

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        document = _document(memory.content, memory.id, encode_record(memory))
        try:
            self._index.insert(document)
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
        docstore = getattr(self._index, "docstore", None)
        getter = getattr(docstore, "get_document", None) if docstore is not None else None
        if not callable(getter):
            getter = getattr(docstore, "get_node", None) if docstore is not None else None
        if not callable(getter):
            return None
        try:
            node = getter(memory_id)
        except Exception:
            return None
        if node is None:
            return None
        return _from_node(node)

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._index, "delete_ref_doc", None)
        if callable(deleter):
            deleter(memory_id, delete_from_docstore=True)
            return
        fallback = getattr(self._index, "delete", None)
        if callable(fallback):
            fallback(memory_id)


def _document(text: str, doc_id: str, metadata: dict[str, str]) -> Any:
    try:
        from llama_index.core import Document
    except ImportError:
        try:
            from llama_index.core.schema import Document
        except ImportError:
            return SimpleNamespace(text=text, doc_id=doc_id, metadata=metadata, id_=doc_id)
    return Document(text=text, doc_id=doc_id, metadata=metadata)


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


def _from_node(node: Any) -> MemoryRecord:
    metadata = getattr(node, "metadata", None) or getattr(node, "extra_info", None) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    memory_id = (
        getattr(node, "doc_id", None)
        or getattr(node, "id_", None)
        or getattr(node, "node_id", None)
        or metadata.get("id")
        or "llama_unknown"
    )
    return decode_record(memory_id=str(memory_id), content=_node_text(node), metadata=metadata)


__all__ = ["LlamaIndexBackend"]
