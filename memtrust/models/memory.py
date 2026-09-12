"""Memory models: :class:`MemoryCandidate` (proposed) and :class:`MemoryRecord` (persisted)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from .._time import utcnow
from .enums import MemoryStatus, TrustLevel
from .provenance import Provenance
from .scope import Scope
from .source import Source

# 0..1 score, optional.
Score = Annotated[float, Field(ge=0.0, le=1.0)]


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class MemoryCandidate(BaseModel):
    """A proposed memory, before any persistence decision has been made.

    ``authority`` and ``confidence`` are deliberately distinct: an extractor
    may be 99% *confident* it read "refunds need no approval" from an email,
    while the email's *authority* to set refund policy is ~zero.
    """

    model_config = ConfigDict(extra="forbid")

    content: str
    source: Source = Field(default_factory=lambda: Source(type="unspecified"))
    scope: Scope = Field(default_factory=Scope)
    authority: Score | None = Field(
        default=None,
        description="Permission to assert this. Defaults to the source's implied authority.",
    )
    confidence: Score | None = Field(
        default=None, description="Extraction/derivation certainty (NOT authority)."
    )
    metadata: dict[str, object] = Field(default_factory=dict)
    id: str | None = Field(default=None, description="Optional caller-proposed id.")
    derived_from: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @property
    def effective_authority(self) -> float:
        """Authority to use for decisions.

        Security model: an explicit ``authority`` may only *lower* the value
        below what the source's trust implies — it can never raise it. This
        prevents untrusted input from defeating authority controls by simply
        declaring ``authority=1.0``. To grant more authority, use a more
        trusted source.
        """
        source_default = self.source.default_authority
        if self.authority is not None:
            return min(self.authority, source_default)
        return source_default

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
        source_ids = [self.source.id] if self.source.id else []
        prov = provenance or Provenance(
            source_ids=source_ids, derived_from=list(self.derived_from)
        )
        return MemoryRecord(
            id=record_id,
            content=content if content is not None else self.content,
            source=self.source,
            scope=self.scope,
            provenance=prov,
            authority=self.effective_authority,
            trust=self.source.trust,
            confidence=self.confidence,
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
    source: Source = Field(default_factory=lambda: Source(type="unspecified"))
    scope: Scope = Field(default_factory=Scope)
    provenance: Provenance = Field(default_factory=Provenance)
    authority: Score = 0.0
    trust: TrustLevel = TrustLevel.UNTRUSTED
    confidence: Score | None = None
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
