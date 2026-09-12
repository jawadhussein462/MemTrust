"""Audit event model and the :class:`AuditStore` repository interface."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from .._time import utcnow
from ..models.enums import Action, AuditEventType, Risk


class AuditEvent(BaseModel):
    """One entry in the trust ledger.

    Serializable to JSON. Never contains raw secrets: ``content_preview`` is
    redacted and truncated before the event is created.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    type: AuditEventType
    timestamp: datetime = Field(default_factory=utcnow)
    memory_id: str | None = None
    action: Action | None = None
    risk: Risk | None = None
    finding_codes: list[str] = Field(default_factory=list)
    finding_count: int = 0
    policy_matches: list[str] = Field(default_factory=list)
    content_preview: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    def to_json(self) -> str:
        return self.model_dump_json()


@runtime_checkable
class AuditStore(Protocol):
    """Repository for audit events. Implementations must not require a database."""

    def append(self, event: AuditEvent) -> None: ...

    def list(
        self,
        *,
        type: AuditEventType | None = None,
        memory_id: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]: ...


def matches_filters(
    event: AuditEvent,
    *,
    type: AuditEventType | None,
    memory_id: str | None,
) -> bool:
    """Shared filter predicate used by store implementations."""
    if type is not None and event.type != type:
        return False
    return not (memory_id is not None and event.memory_id != memory_id)


__all__ = ["AuditEvent", "AuditStore", "matches_filters"]
