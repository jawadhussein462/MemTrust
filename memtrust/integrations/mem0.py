"""Mem0 backend adapter.

Wraps a Mem0 ``Memory`` or ``MemoryClient`` so it can be protected by
MemTrust. The full MemTrust record is stored in Mem0 ``metadata`` under the
``memtrust`` key and reconstructed on read.

Install with ``pip install "memtrust[mem0]"``.

Note: Mem0's call shapes vary across versions. Mem0 2.x requires an entity
id (``user_id`` / ``agent_id`` / ``run_id``) on add and inside ``filters`` on
search; the platform ``MemoryClient`` also takes identity inside ``filters``
on add and returns async ``PENDING`` add responses when ``infer=True``.
Response shapes vary too (bare list vs. ``{"results": [...]}``; ``memory``
vs. ``text`` keys). This adapter inspects the client's signatures and is
defensive about those differences; verify against your installed version.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

from ..exceptions import BackendError
from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ._codec import decode_record

_MT_KEY = "memtrust"


class Mem0Backend:
    """Adapter from Mem0 to the MemTrust :class:`MemoryBackend` protocol.

    ``infer=False`` stores the already-formed MemTrust record as-is. The
    platform ``MemoryClient`` otherwise extracts facts asynchronously and
    returns a ``PENDING`` response with no memory id.

    Pass ``user_id`` / ``agent_id`` / ``run_id`` to scope memories to an
    entity (Mem0 2.x requires at least one). Status changes (supersede,
    quarantine, revoke) are written in place with ``client.update``.
    """

    def __init__(
        self,
        client: Any,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        run_id: str | None = None,
        infer: bool = False,
        search_filters: bool | None = None,
    ) -> None:
        if not (hasattr(client, "add") and hasattr(client, "search")):
            raise BackendError("Mem0 client must provide .add() and .search().")
        self._client = client
        self._infer = infer
        self._identity = {
            k: v for k, v in (("user_id", user_id), ("agent_id", agent_id), ("run_id", run_id)) if v
        }
        platform = _is_platform_client(client)
        search_params = _params(client.search)
        self._search_filters = (
            platform or "filters" in search_params if search_filters is None else search_filters
        )
        self._top_k = self._search_filters or "top_k" in search_params
        self._identity_in_add_filters = platform or (
            "filters" in _params(client.add) and "user_id" not in _params(client.add)
        )

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        # JSON string survives Mem0's metadata flattening (nested dicts become
        # dotted-path lists on some list endpoints).
        kwargs: dict[str, Any] = {"metadata": _metadata(memory), "infer": self._infer}
        if self._identity:
            if self._identity_in_add_filters:
                kwargs["filters"] = dict(self._identity)
            else:
                kwargs.update(self._identity)
        try:
            res = self._client.add(memory.content, **kwargs)
        except Exception as exc:
            raise BackendError(f"Mem0 add failed: {exc}") from exc
        new_id = _extract_id(res)
        if new_id:
            return memory.model_copy(update={"id": new_id})
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        kwargs: dict[str, Any] = {"top_k": limit} if self._top_k else {"limit": limit}
        if self._identity:
            if self._search_filters:
                kwargs["filters"] = dict(self._identity)
            else:
                kwargs.update(self._identity)
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
        return _to_record(item) if isinstance(item, dict) and item else None

    def delete(self, memory_id: str) -> None:
        deleter = getattr(self._client, "delete", None)
        if callable(deleter):
            deleter(memory_id)

    def set_status(self, memory_id: str, status: MemoryStatus) -> None:
        """Rewrite the stored record's status in place (no duplicate memory)."""
        record = self.get(memory_id)
        if record is None:
            return
        updater = getattr(self._client, "update", None)
        if not callable(updater) or not _accepts(updater, "metadata"):
            raise BackendError(
                "Mem0 client cannot update metadata in place; upgrade mem0ai to change "
                "memory status without duplicating it."
            )
        updated = record.model_copy(update={"status": status})
        try:
            updater(memory_id, metadata=_metadata(updated))
        except Exception as exc:
            raise BackendError(f"Mem0 update failed: {exc}") from exc


def _metadata(memory: MemoryRecord) -> dict[str, str]:
    return {_MT_KEY: json.dumps(memory.model_dump(mode="json"))}


def _params(fn: Any) -> set[str]:
    """Explicitly named parameters of ``fn`` (empty when unreadable)."""
    try:
        return set(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        return set()


def _accepts(fn: Any, name: str) -> bool:
    """Whether ``fn`` accepts keyword ``name`` (named, via ``**kwargs``, or unknown)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return True
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _is_platform_client(client: Any) -> bool:
    """True for mem0.client MemoryClient, which takes identity inside ``filters``."""
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


def _stored_content(stored: Any) -> str | None:
    if isinstance(stored, str):
        try:
            stored = json.loads(stored)
        except json.JSONDecodeError:
            return None
    if isinstance(stored, dict) and isinstance(stored.get("content"), str):
        return str(stored["content"])
    return None


def _to_record(item: dict[str, Any]) -> MemoryRecord:
    metadata = item.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    mem0_id = str(item.get("id") or "mem_unknown")
    # Prefer MemTrust's stored content: Mem0 inference can rewrite text
    # (including quarantined poisoning attempts).
    content = _stored_content(metadata.get(_MT_KEY))
    if content is None:
        content = str(item.get("memory") or item.get("text") or "")
    return decode_record(metadata, id=mem0_id, content=content)


__all__ = ["Mem0Backend"]
