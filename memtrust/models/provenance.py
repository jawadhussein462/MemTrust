"""Lineage of a memory: what it came from and who has touched it."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class Retrieval(BaseModel):
    """A record that a memory was returned to some agent at some time."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str | None = None
    session_id: str | None = None
    at: datetime | None = None


class Provenance(BaseModel):
    """Traceability for a persisted memory.

    Lineage is represented with IDs, not a graph database. This is enough to
    answer "what was this derived from?" and "who has read it?" and to power
    source revocation.

    Example::

        Provenance(source_ids=["ticket_123"], derived_from=["mem_1", "mem_2"])
    """

    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] = Field(default_factory=list, description="Originating source document IDs.")
    derived_from: list[str] = Field(
        default_factory=list, description="IDs of memories this one was derived from."
    )
    retrievals: list[Retrieval] = Field(
        default_factory=list, description="Recorded retrievals (only what audit actually observed)."
    )

    def record_retrieval(self, agent_id: str | None, session_id: str | None, at: datetime) -> None:
        self.retrievals.append(Retrieval(agent_id=agent_id, session_id=session_id, at=at))


__all__ = ["Provenance", "Retrieval"]
