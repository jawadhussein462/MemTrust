"""Qdrant vector-store adapter.

Wraps a Qdrant client so RAG points and long-term memories are gated by
MemTrust. The full record lives in point payload under ``memtrust``.

If you pass ``embed``, search uses vector similarity. Without an embedder,
search falls back to payload scroll plus substring match (useful in tests
and keyword-only setups).

Install with ``pip install "memtrust[qdrant]"``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from ..exceptions import BackendError
from ..models.memory import MemoryRecord
from ._codec import decode_record, encode_record

EmbedFn = Callable[[str], Sequence[float]]


class QdrantBackend:
    """Adapter from a Qdrant client to the MemTrust backend protocol.

    ``embed`` should return a dense vector for a string. When omitted, points
    are stored with an empty vector and search uses payload scan.
    """

    def __init__(
        self,
        client: Any,
        *,
        collection_name: str = "memtrust",
        embed: EmbedFn | None = None,
    ) -> None:
        if not hasattr(client, "upsert"):
            raise BackendError("Qdrant client must provide .upsert().")
        self._client = client
        self._collection = collection_name
        self._embed = embed

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        vector = list(self._embed(memory.content)) if self._embed else []
        point = {
            "id": memory.id,
            "vector": vector,
            "payload": {**encode_record(memory), "content": memory.content},
        }
        try:
            self._client.upsert(collection_name=self._collection, points=[point])
        except Exception as exc:
            raise BackendError(f"Qdrant upsert failed: {exc}") from exc
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        try:
            points = self._query_points(query, limit=limit)
        except Exception as exc:
            raise BackendError(f"Qdrant search failed: {exc}") from exc
        return [self._to_record(point) for point in points]

    def get(self, memory_id: str) -> MemoryRecord | None:
        retrieve = getattr(self._client, "retrieve", None)
        if not callable(retrieve):
            return None
        try:
            points = retrieve(collection_name=self._collection, ids=[memory_id])
        except Exception:
            return None
        if not points:
            return None
        return self._to_record(points[0])

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._client, "delete", None)
        if callable(deleter):
            deleter(
                collection_name=self._collection,
                points_selector={"points": [memory_id]},
            )

    def _query_points(self, query: str, *, limit: int) -> list[Any]:
        if self._embed and hasattr(self._client, "query_points"):
            res = self._client.query_points(
                collection_name=self._collection,
                query=list(self._embed(query)),
                limit=limit,
            )
            return list(getattr(res, "points", None) or res or [])
        if self._embed and hasattr(self._client, "search"):
            return list(
                self._client.search(
                    collection_name=self._collection,
                    query_vector=list(self._embed(query)),
                    limit=limit,
                )
                or []
            )
        scroll = getattr(self._client, "scroll", None)
        if not callable(scroll):
            return []
        res = scroll(collection_name=self._collection, limit=max(limit, 100))
        points = res[0] if isinstance(res, tuple) else res
        needle = (query or "").lower()
        hits = []
        for point in points or []:
            payload = _payload(point)
            content = str(payload.get("content") or "")
            if not needle or needle in content.lower():
                hits.append(point)
            if len(hits) >= limit:
                break
        return hits

    def _to_record(self, point: Any) -> MemoryRecord:
        payload = _payload(point)
        memory_id = str(getattr(point, "id", None) or payload.get("id") or "qdrant_unknown")
        if isinstance(point, dict):
            memory_id = str(point.get("id") or memory_id)
        content = str(payload.get("content") or "")
        return decode_record(memory_id=memory_id, content=content, metadata=payload)


def _payload(point: Any) -> dict[str, Any]:
    if isinstance(point, dict):
        payload = point.get("payload") or {}
        return payload if isinstance(payload, dict) else {}
    payload = getattr(point, "payload", None) or {}
    return payload if isinstance(payload, dict) else {}


__all__ = ["QdrantBackend"]
