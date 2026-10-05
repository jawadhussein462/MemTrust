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

    read_checks: bool = Field(
        default=True,
        description=(
            "Run read-capable checks (secrets, injection, poisoning) on every retrieved "
            "record and withhold flagged ones. Core status/expiry filtering always applies."
        ),
    )

    neighbor_limit: int = Field(
        default=20, ge=0, description="Max existing records fetched to compare a candidate against."
    )


__all__ = ["Config"]
