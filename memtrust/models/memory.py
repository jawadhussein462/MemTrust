"""Memory models: :class:`MemoryCandidate` (proposed) and :class:`MemoryRecord` (persisted)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .._time import utcnow
from .enums import MemoryStatus
from .provenance import Provenance


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class MemoryCandidate(BaseModel):
    """A proposed memory, before any persistence decision has been made."""

    model_config = ConfigDict(extra="forbid")

    content: str
    excerpt: str | None = Field(
        default=None,
        description="Optional raw text the memory was derived from (generalization checks).",
    )
    metadata: dict[str, object] = Field(default_factory=dict)
    id: str | None = Field(default=None, description="Optional caller-proposed id.")
    derived_from: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    def to_record(
        self,
        *,
        id: str | None = None,
        content: str | None = None,
        status: MemoryStatus = MemoryStatus.ACTIVE,
        supersedes: list[str] | None = None,
        provenance: Provenance | None = None,
    ) -> MemoryRecord:
        """Materialize this candidate into a persisted record."""
        record_id = id or self.id or _new_id("mem")
        prov = provenance or Provenance(derived_from=list(self.derived_from))
        return MemoryRecord(
            id=record_id,
            content=content if content is not None else self.content,
            provenance=prov,
            status=status,
            created_at=self.created_at,
            updated_at=utcnow(),
            expires_at=self.expires_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            supersedes=list(supersedes or []),
            derived_from=list(self.derived_from),
            metadata=dict(self.metadata),
        )


class MemoryRecord(BaseModel):
    """A persisted memory and everything needed to reason about it later."""

    model_config = ConfigDict(extra="forbid")

    id: str
    content: str
    provenance: Provenance = Field(default_factory=Provenance)
    status: MemoryStatus = MemoryStatus.ACTIVE
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    supersedes: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)

    def is_expired(self, now: datetime) -> bool:
        if self.expires_at is not None and now >= self.expires_at:
            return True
        return self.valid_until is not None and now > self.valid_until

    def is_not_yet_valid(self, now: datetime) -> bool:
        return self.valid_from is not None and now < self.valid_from

    def is_live(self, now: datetime) -> bool:
        """Active, not expired, and within any validity window."""
        return (
            self.status == MemoryStatus.ACTIVE
            and not self.is_expired(now)
            and not self.is_not_yet_valid(now)
        )


__all__ = ["MemoryCandidate", "MemoryRecord"]
