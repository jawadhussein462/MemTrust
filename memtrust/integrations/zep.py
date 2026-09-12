"""Zep backend adapter — EXPERIMENTAL.

Zep retired the classic ``memory.search`` / ``memory.session_search`` APIs in
May 2025 in favour of the graph API (``zep-cloud``). This adapter targets the
graph API and is intentionally minimal and clearly marked experimental: verify
against your installed ``zep-cloud`` version before relying on it.

Install with ``pip install "memtrust[zep]"``.
"""

from __future__ import annotations

from typing import Any

from ..exceptions import BackendError, IntegrationError
from ..models.memory import MemoryRecord
from ..models.scope import Scope

_MT_MARKER = "memtrust::"


class ZepBackend:
    """Experimental adapter onto Zep's graph API.

    Records are serialized into graph ``data`` with a marker prefix so they can
    be recovered on search. Graph search result shapes vary; this adapter is
    defensive and falls back to minimal reconstruction.
    """

    def __init__(self, client: Any, *, group_id: str | None = None) -> None:
        if not hasattr(client, "graph"):
            raise IntegrationError(
                "Expected a zep-cloud client with a .graph API. "
                "Install with: pip install 'memtrust[zep]'"
            )
        self._client = client
        self._group_id = group_id

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        payload = _MT_MARKER + memory.model_dump_json()
        kwargs: dict[str, Any] = {"type": "text", "data": payload}
        if memory.scope.user_id:
            kwargs["user_id"] = memory.scope.user_id
        elif self._group_id:
            kwargs["group_id"] = self._group_id
        try:
            self._client.graph.add(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"Zep graph.add failed: {exc}") from exc
        return memory

    def search(self, query: str, *, scope: Scope, limit: int = 10) -> list[MemoryRecord]:
        kwargs: dict[str, Any] = {"query": query, "limit": limit}
        if scope.user_id:
            kwargs["user_id"] = scope.user_id
        elif self._group_id:
            kwargs["group_id"] = self._group_id
        try:
            res = self._client.graph.search(**kwargs)
        except Exception as exc:  # noqa: BLE001
            raise BackendError(f"Zep graph.search failed: {exc}") from exc
        return _parse_search(res, scope)

    def get(self, memory_id: str) -> MemoryRecord | None:  # pragma: no cover - experimental
        raise NotImplementedError("ZepBackend.get is not supported by the graph API yet.")

    def delete(self, memory_id: str) -> None:  # pragma: no cover - experimental
        raise NotImplementedError("ZepBackend.delete is not supported by the graph API yet.")


def _parse_search(res: Any, scope: Scope) -> list[MemoryRecord]:
    edges = getattr(res, "edges", None)
    nodes = getattr(res, "nodes", None)
    items = list(edges or []) + list(nodes or [])
    records: list[MemoryRecord] = []
    for item in items:
        data = getattr(item, "fact", None) or getattr(item, "summary", None) or ""
        if isinstance(data, str) and data.startswith(_MT_MARKER):
            try:
                records.append(MemoryRecord.model_validate_json(data[len(_MT_MARKER):]))
                continue
            except Exception:  # noqa: BLE001
                pass
        if data:
            records.append(
                MemoryRecord(id="zep_unknown", content=str(data), scope=Scope(tenant_id=scope.tenant_id))
            )
    return records


__all__ = ["ZepBackend"]
