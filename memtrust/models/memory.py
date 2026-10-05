"""Memory models: :class:`MemoryCandidate` (one record under scan) and :class:`MemoryRecord`."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .enums import MemoryStatus


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MemoryCandidate(BaseModel):
    """One stored record as a check sees it during a scan."""

    model_config = ConfigDict(extra="forbid")

    content: str
    metadata: dict[str, object] = Field(default_factory=dict)
    id: str | None = Field(default=None, description="Record id, when the store has one.")
    derived_from: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


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
