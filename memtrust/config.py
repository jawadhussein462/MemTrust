"""Runtime configuration for a MemTrust instance.

Configuration is passed by dependency injection (constructor argument), never
read from module-level globals. Every field has a safe default so that
``MemTrust()`` works out of the box.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Config(BaseModel):
    """Tunable behaviour for checks and enforcement."""

    model_config = ConfigDict(extra="forbid")

    fail_closed: bool = Field(
        default=True,
        description="On internal check errors, treat as a blocking violation rather than allowing.",
    )

    # Correctness tuning
    duplicate_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    contradiction_enabled: bool = Field(default=True)
    neighbor_limit: int = Field(
        default=20, ge=0, description="Max existing records fetched to compare a candidate against."
    )

    # Protected-backend behaviour
    store_quarantined: bool = Field(
        default=True,
        description="Persist quarantined writes with QUARANTINED status instead of dropping.",
    )
    raise_on_blocked_add: bool = Field(
        default=False, description="If True, protected .add raises when a write is blocked."
    )


__all__ = ["Config"]
