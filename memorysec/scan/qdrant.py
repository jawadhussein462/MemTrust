"""Read-only Qdrant collection scanner."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..exceptions import ConfigurationError
from ..models.memory import MemoryRecord
from .source import missing_extra, take, text_from_payload, to_record

_QDRANT_PAGE = 256


class QdrantScanSource:
    """Scroll every point in a Qdrant collection. Never upserts or deletes."""

    def __init__(
        self,
        *,
        url: str | None = None,
        collection: str,
        api_key: str | None = None,
        client: Any | None = None,
        text_field: str | None = None,
    ) -> None:
        if client is None and not url:
            raise ConfigurationError("qdrant scan needs --url.")
        self._url = url
        self._api_key = api_key
        self._collection = collection
        self._client = client
        self._text_field = text_field

    def records(
        self, *, batch_size: int = _QDRANT_PAGE, sample: int | None = None
    ) -> Iterator[MemoryRecord]:
        client = self._client if self._client is not None else self._open()
        yield from take(self._scroll(client, batch_size=batch_size), sample=sample)

    def _open(self) -> Any:
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise missing_extra("Qdrant", "qdrant") from exc
        return QdrantClient(url=self._url, api_key=self._api_key)

    def _scroll(self, client: Any, *, batch_size: int) -> Iterator[MemoryRecord]:
        offset: Any = None
        while True:
            try:
                points, offset = client.scroll(
                    collection_name=self._collection,
                    limit=batch_size,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )
            except Exception as exc:
                raise ConfigurationError(f"Qdrant scroll failed: {exc}") from exc
            for point in points or []:
                yield self._to_record(point)
            if offset is None:
                return

    def _to_record(self, point: Any) -> MemoryRecord:
        if isinstance(point, dict):
            payload = point.get("payload") or {}
            raw_id = point.get("id")
        else:
            payload = getattr(point, "payload", None) or {}
            raw_id = getattr(point, "id", None)
        payload = payload if isinstance(payload, dict) else {}
        memory_id = payload.get("memorysec_id") or payload.get("id") or raw_id or "qdrant_unknown"
        content = text_from_payload(payload.get("content"), payload, field=self._text_field)
        return to_record(memory_id, content)


__all__ = ["QdrantScanSource"]
