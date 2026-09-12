"""Lineage of a memory: what it came from and who has touched it."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class Retrieval(BaseModel):
    """A record that a memory was returned at some time."""

    model_config = ConfigDict(extra="forbid")

    at: datetime | None = None


class Provenance(BaseModel):
    """Traceability for a persisted memory.

    Lineage is represented with IDs, not a graph database. This is enough to
    answer "what was this derived from?" and to power revocation of a memory
    and anything derived from it.
    """

    model_config = ConfigDict(extra="forbid")

    derived_from: list[str] = Field(
        default_factory=list, description="IDs of memories this one was derived from."
    )
    retrievals: list[Retrieval] = Field(
        default_factory=list, description="Recorded retrievals (only what audit actually observed)."
    )


__all__ = ["Provenance", "Retrieval"]
