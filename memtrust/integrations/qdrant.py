"""Qdrant vector-store adapter.

Wraps a Qdrant client so RAG points and long-term memories are gated by
MemTrust. The point payload stores the document text and MemTrust's record
state (status, validity, lineage), so read enforcement survives a round
trip.

Qdrant point ids must be unsigned integers or UUIDs. MemTrust ids that are
neither are mapped to a stable UUIDv5; the MemTrust id travels in the
payload and is what callers see.

If you pass ``embed``, search uses vector similarity. Without an embedder,
points are stored without vectors and search falls back to a payload scroll
ranked by text similarity (useful in tests and small keyword-only setups).

Install with ``pip install "memtrust[qdrant]"``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Sequence
from typing import Any

from ..exceptions import BackendError
from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ..text import similarity
from ._codec import STATE_KEY, decode_record, encode_state

EmbedFn = Callable[[str], Sequence[float]]

_ID_NAMESPACE = uuid.UUID("6f1d3c8e-5b0a-4c55-9a4e-1f0c7b2d9e31")
_PAGE = 256


def point_id(memory_id: str) -> str | int:
    """Qdrant point id for a MemTrust id (UUIDs and integers pass through)."""
    if memory_id.isdigit():
        return int(memory_id)
    try:
        return str(uuid.UUID(memory_id))
    except ValueError:
        return str(uuid.uuid5(_ID_NAMESPACE, memory_id))


class QdrantBackend:
    """Adapter from a Qdrant client to the MemTrust backend protocol.

    ``embed`` should return a dense vector for a string. When omitted, points
    are stored with no vector and search uses payload scan.
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
        vector: Any = list(self._embed(memory.content)) if self._embed else {}
        point = _point(point_id(memory.id), vector, _payload_for(memory))
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
        return [_to_record(point) for point in points]

    def get(self, memory_id: str) -> MemoryRecord | None:
        try:
            points = self._client.retrieve(
                collection_name=self._collection,
                ids=[point_id(memory_id)],
                with_payload=True,
            )
        except Exception:
            return None
        if not points:
            return None
        return _to_record(points[0])

    def delete(self, memory_id: str) -> None:
        self._client.delete(
            collection_name=self._collection,
            points_selector=_ids_selector([point_id(memory_id)]),
        )

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        record = self.get(memory_id)
        if record is None:
            return
        updated = record.model_copy(update={"status": status})
        try:
            self._client.set_payload(
                collection_name=self._collection,
                payload={STATE_KEY: encode_state(updated)},
                points=[point_id(memory_id)],
            )
        except Exception as exc:
            raise BackendError(f"Qdrant set_payload failed: {exc}") from exc

    def all(self) -> Iterator[MemoryRecord]:
        """Every point in the collection, paged via ``scroll``."""
        offset: Any = None
        while True:
            points, offset = self._client.scroll(
                collection_name=self._collection,
                limit=_PAGE,
                offset=offset,
                with_payload=True,
            )
            for point in points or []:
                yield _to_record(point)
            if offset is None:
                return

    def _query_points(self, query: str, *, limit: int) -> list[Any]:
        if self._embed and hasattr(self._client, "query_points"):
            res = self._client.query_points(
                collection_name=self._collection,
                query=list(self._embed(query)),
                limit=limit,
                with_payload=True,
            )
            return list(getattr(res, "points", None) or [])
        if self._embed and hasattr(self._client, "search"):
            return list(
                self._client.search(
                    collection_name=self._collection,
                    query_vector=list(self._embed(query)),
                    limit=limit,
                )
                or []
            )
        # Keyword mode: scan the collection and rank by text similarity, like
        # InMemoryBackend. Linear in collection size — pass ``embed`` for scale.
        scored: list[tuple[float, Any]] = []
        offset: Any = None
        while True:
            points, offset = self._client.scroll(
                collection_name=self._collection,
                limit=_PAGE,
                offset=offset,
                with_payload=True,
            )
            for point in points or []:
                content = str(_payload(point).get("content") or "")
                scored.append((similarity(query, content) if query else 0.0, point))
            if offset is None:
                break
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [point for _, point in scored[:limit]]


_ID_KEY = "memtrust_id"


def _payload_for(memory: MemoryRecord) -> dict[str, Any]:
    return {_ID_KEY: memory.id, "content": memory.content, STATE_KEY: encode_state(memory)}


def _point(pid: str | int, vector: Any, payload: dict[str, Any]) -> Any:
    try:
        from qdrant_client.models import PointStruct
    except ImportError:
        return {"id": pid, "vector": vector, "payload": payload}
    return PointStruct(id=pid, vector=vector, payload=payload)


def _ids_selector(ids: list[str | int]) -> Any:
    try:
        from qdrant_client.models import PointIdsList
    except ImportError:
        return {"points": ids}
    return PointIdsList(points=ids)


def _payload(point: Any) -> dict[str, Any]:
    if isinstance(point, dict):
        payload = point.get("payload") or {}
    else:
        payload = getattr(point, "payload", None) or {}
    return payload if isinstance(payload, dict) else {}


def _to_record(point: Any) -> MemoryRecord:
    payload = _payload(point)
    raw_id = point.get("id") if isinstance(point, dict) else getattr(point, "id", None)
    # Points written by MemTrust carry the caller-visible id; others use the point id.
    memory_id = payload.get(_ID_KEY) or (raw_id if raw_id is not None else "qdrant_unknown")
    return decode_record(payload, id=str(memory_id), content=str(payload.get("content") or ""))


__all__ = ["QdrantBackend", "point_id"]
