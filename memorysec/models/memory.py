"""The two memory objects: `MemoryCandidate` during a scan, `MemoryRecord` in a store."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .enums import MemoryStatus


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MemoryCandidate(BaseModel):
    """One memory as a check sees it during a scan.

    Attributes:
        content: The text to inspect.
        metadata: Store fields copied onto the candidate. Checks may read
            them. Do not put secrets here if a report will be forwarded.
        id: Record id from the store. `None` when the input was only a string.
        derived_from: Ids of records this one was built from, if the store
            tracks that.
        created_at: When the record was created. Defaults to now, in UTC.
    """

    model_config = ConfigDict(extra="forbid")

    content: str
    metadata: dict[str, object] = Field(default_factory=dict)
    id: str | None = Field(default=None, description="Record id, when the store has one.")
    derived_from: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class MemoryRecord(BaseModel):
    """One memory as it sits in a store.

    Attributes:
        id: Store id. Required.
        content: The text that will be scanned.
        status: `active`, `revoked`, or `quarantined`. Defaults to active.
            TrustRAG skips neighbours that are not active.
        created_at: When the record was first stored. Defaults to now, in UTC.
        updated_at: When the record last changed. Defaults to now, in UTC.
        derived_from: Ids this record was built from.
        metadata: Extra store fields. Empty by default.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    content: str
    status: MemoryStatus = MemoryStatus.ACTIVE
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    derived_from: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


__all__ = ["MemoryCandidate", "MemoryRecord"]
