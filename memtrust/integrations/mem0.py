"""Mem0 backend adapter.

Wraps a Mem0 ``Memory`` or ``MemoryClient`` so it can be protected by
MemTrust. The full MemTrust record is stored in Mem0 ``metadata`` under the
``memtrust`` key and reconstructed on read.

Install with ``pip install "memtrust[mem0]"``.

Note: Mem0's response shapes vary across versions (bare list vs.
``{"results": [...]}``; ``memory`` vs. ``text`` keys). The platform
``MemoryClient`` (v2+) requires identity in ``filters`` on search and
returns async ``PENDING`` add responses when ``infer=True``. This adapter
is defensive about those differences; verify against your installed version.
"""

from __future__ import annotations

import json
from typing import Any

from ..exceptions import BackendError
from ..models.memory import MemoryRecord

_MT_KEY = "memtrust"


class Mem0Backend:
    """Adapter from Mem0 to the MemTrust :class:`MemoryBackend` protocol.

    ``infer=False`` stores the already-formed MemTrust record as-is. The
    platform ``MemoryClient`` otherwise extracts facts asynchronously and
    returns a ``PENDING`` response with no memory id.

    Identity handling is auto-detected: platform ``MemoryClient`` search uses
    ``filters`` + ``top_k``; OSS ``Memory`` and test doubles keep top-level
    ``limit``.
    """

    def __init__(
        self,
        client: Any,
        *,
        infer: bool = False,
        search_filters: bool | None = None,
    ) -> None:
        if not (hasattr(client, "add") and hasattr(client, "search")):
            raise BackendError("Mem0 client must provide .add() and .search().")
        self._client = client
        self._infer = infer
        self._search_filters = (
            _client_uses_search_filters(client) if search_filters is None else search_filters
        )

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        # JSON string survives Mem0's metadata flattening (nested dicts become
        # dotted-path lists on some list endpoints).
        kwargs: dict[str, Any] = {
            "metadata": {_MT_KEY: json.dumps(memory.model_dump(mode="json"))},
            "infer": self._infer,
        }
        try:
            res = self._client.add(memory.content, **kwargs)
        except Exception as exc:
            raise BackendError(f"Mem0 add failed: {exc}") from exc
        new_id = _extract_id(res)
        if new_id:
            return memory.model_copy(update={"id": new_id})
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        if self._search_filters:
            kwargs: dict[str, Any] = {"top_k": limit}
        else:
            kwargs = {"limit": limit}
        try:
            res = self._client.search(query, **kwargs)
        except Exception as exc:
            raise BackendError(f"Mem0 search failed: {exc}") from exc
        return [_to_record(item) for item in _extract_results(res)]

    def get(self, memory_id: str) -> MemoryRecord | None:
        getter = getattr(self._client, "get", None)
        if not callable(getter):
            return None
        try:
            item = getter(memory_id)
        except Exception:
            return None
        return _to_record(item) if item else None

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._client, "delete", None)
        if callable(deleter):
            deleter(memory_id)


def _client_uses_search_filters(client: Any) -> bool:
    """True for mem0.client MemoryClient, which rejects top-level user_id on search."""
    cls = type(client)
    module = getattr(cls, "__module__", "")
    name = cls.__name__
    return module.startswith("mem0.client") and name.endswith("MemoryClient")


def _extract_results(res: Any) -> list[dict[str, Any]]:
    if res is None:
        return []
    if isinstance(res, dict):
        results = res.get("results", res.get("memories", []))
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
        return []
    if isinstance(res, list):
        return [item for item in res if isinstance(item, dict)]
    return []


def _extract_id(res: Any) -> str | None:
    if isinstance(res, dict):
        # Do not treat event_id as a memory id (PENDING adds return only that).
        if isinstance(res.get("id"), str) and res["id"]:
            return res["id"]
        results = res.get("results")
        if isinstance(results, list) and results:
            first = results[0]
            if isinstance(first, dict):
                return str(first.get("id") or first.get("memory_id") or "") or None
    if isinstance(res, list) and res and isinstance(res[0], dict):
        first = res[0]
        return str(first.get("id") or first.get("memory_id") or "") or None
    return None


def _parse_stored_metadata(stored: Any) -> dict[str, Any] | None:
    if isinstance(stored, dict):
        return stored
    if isinstance(stored, str):
        try:
            parsed = json.loads(stored)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _to_record(item: dict[str, Any]) -> MemoryRecord:
    metadata = item.get("metadata") or {}
    stored = metadata.get(_MT_KEY) if isinstance(metadata, dict) else None
    payload = _parse_stored_metadata(stored)
    if payload is not None:
        record = MemoryRecord.model_validate(payload)
        # Prefer MemTrust's stored content: Mem0 inference can rewrite text
        # (including quarantined poisoning attempts).
        return record.model_copy(update={"id": str(item.get("id", record.id))})
    return MemoryRecord(
        id=str(item.get("id", "mem_unknown")),
        content=item.get("memory") or item.get("text") or "",
    )


__all__ = ["Mem0Backend"]
