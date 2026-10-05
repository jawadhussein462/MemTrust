"""Memory models: :class:`MemoryCandidate` (proposed) and :class:`MemoryRecord` (persisted)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .enums import MemoryStatus


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MemoryCandidate(BaseModel):
    """A proposed memory, before any persistence decision has been made."""

    model_config = ConfigDict(extra="forbid")

    content: str
    metadata: dict[str, object] = Field(default_factory=dict)
    id: str | None = Field(default=None, description="Optional caller-proposed id.")
    derived_from: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)

    def to_record(
        self,
        *,
        id: str | None = None,
        content: str | None = None,
        status: MemoryStatus = MemoryStatus.ACTIVE,
    ) -> MemoryRecord:
        """Materialize this candidate into a persisted record."""
        record_id = id or self.id or _new_id("mem")
        return MemoryRecord(
            id=record_id,
            content=content if content is not None else self.content,
            status=status,
            created_at=self.created_at,
            updated_at=_utcnow(),
            derived_from=list(self.derived_from),
            metadata=dict(self.metadata),
        )


class MemoryRecord(BaseModel):
    """A persisted memory and everything needed to reason about it later."""

    model_config = ConfigDict(extra="forbid")

    id: str
    content: str
    status: MemoryStatus = MemoryStatus.ACTIVE
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    derived_from: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


__all__ = ["MemoryCandidate", "MemoryRecord"]
