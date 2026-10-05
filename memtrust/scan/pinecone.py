"""Read-only Pinecone index scanner."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..exceptions import ConfigurationError
from ..models.memory import MemoryRecord
from .source import missing_extra, take, text_from_payload, to_record

_PINECONE_PAGE = 100


class PineconeScanSource:
    """List vector ids and fetch metadata. Never upserts or deletes.

    ``index`` is a Pinecone Index handle (for tests). Otherwise the SDK is
    opened with ``api_key`` / ``PINECONE_API_KEY`` and ``index`` name.
    """

    def __init__(
        self,
        *,
        index: str | None = None,
        api_key: str | None = None,
        host: str | None = None,
        namespace: str = "",
        text_field: str | None = None,
        handle: Any | None = None,
    ) -> None:
        if handle is None and not index:
            raise ConfigurationError("pinecone scan needs --index.")
        self._index_name = index
        self._api_key = api_key
        self._host = host
        self._namespace = namespace
        self._text_field = text_field
        self._handle = handle

    def records(
        self, *, batch_size: int = _PINECONE_PAGE, sample: int | None = None
    ) -> Iterator[MemoryRecord]:
        index = self._handle if self._handle is not None else self._open()
        yield from take(self._pages(index, batch_size=batch_size), sample=sample)

    def _open(self) -> Any:
        try:
            from pinecone import Pinecone
        except ImportError as exc:
            raise missing_extra("Pinecone", "pinecone") from exc
        kwargs: dict[str, Any] = {}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        client = Pinecone(**kwargs)
        if self._host:
            return client.Index(host=self._host)
        return client.Index(self._index_name)

    def _pages(self, index: Any, *, batch_size: int) -> Iterator[MemoryRecord]:
        list_ids = getattr(index, "list", None)
        if not callable(list_ids):
            raise ConfigurationError(
                "This Pinecone index cannot list ids. Use a serverless index, "
                "or pass a handle that implements .list() and .fetch()."
            )
        try:
            pages = list_ids(namespace=self._namespace, limit=batch_size)
        except TypeError:
            pages = list_ids()
        except Exception as exc:
            raise ConfigurationError(f"Pinecone list failed: {exc}") from exc
        for id_page in pages:
            ids = [str(i) for i in (id_page or [])]
            if not ids:
                continue
            try:
                fetched = index.fetch(ids=ids, namespace=self._namespace)
            except TypeError:
                fetched = index.fetch(ids)
            except Exception as exc:
                raise ConfigurationError(f"Pinecone fetch failed: {exc}") from exc
            for memory_id, vector in _vectors(fetched).items():
                metadata = _metadata(vector)
                content = text_from_payload(None, metadata, field=self._text_field)
                yield to_record(memory_id, content)


def _vectors(fetched: Any) -> dict[str, Any]:
    if isinstance(fetched, dict):
        vectors = fetched.get("vectors") or fetched
    else:
        vectors = getattr(fetched, "vectors", None) or {}
    if not isinstance(vectors, dict):
        return {}
    return {str(k): v for k, v in vectors.items()}


def _metadata(vector: Any) -> dict[str, Any]:
    if isinstance(vector, dict):
        meta = vector.get("metadata") or {}
    else:
        meta = getattr(vector, "metadata", None) or {}
    return meta if isinstance(meta, dict) else {}


__all__ = ["PineconeScanSource"]
