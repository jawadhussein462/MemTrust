"""In-memory audit store (default). No persistence, no dependencies."""

from __future__ import annotations

from ..models.enums import AuditEventType
from .base import AuditEvent, matches_filters


class InMemoryAuditStore:
    """Keeps audit events in a list. Handy for tests and local development."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def list(
        self,
        *,
        type: AuditEventType | None = None,
        memory_id: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        out = [e for e in self._events if matches_filters(e, type=type, memory_id=memory_id)]
        if limit is not None:
            out = out[-limit:]
        return out

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


__all__ = ["InMemoryAuditStore"]
