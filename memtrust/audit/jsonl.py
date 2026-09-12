"""JSONL audit store: append-only newline-delimited JSON on disk."""

from __future__ import annotations

from pathlib import Path

from ..models.enums import AuditEventType
from .base import AuditEvent, matches_filters


class JSONLAuditStore:
    """Append audit events to a ``.jsonl`` file, one JSON object per line."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json())
            fh.write("\n")

    def list(
        self,
        *,
        type: AuditEventType | None = None,
        tenant_id: str | None = None,
        memory_id: str | None = None,
        source_id: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        events: list[AuditEvent] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                event = AuditEvent.model_validate_json(line)
                if matches_filters(
                    event,
                    type=type,
                    tenant_id=tenant_id,
                    memory_id=memory_id,
                    source_id=source_id,
                ):
                    events.append(event)
        if limit is not None:
            events = events[-limit:]
        return events


__all__ = ["JSONLAuditStore"]
