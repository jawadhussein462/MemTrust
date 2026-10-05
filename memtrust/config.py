"""Runtime configuration for a MemTrust instance.

Configuration is passed by dependency injection (constructor argument), never
read from module-level globals. Every field has a safe default so that
``MemTrust()`` works out of the box.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Config(BaseModel):
    """Tunable behaviour for checks."""

    model_config = ConfigDict(extra="forbid")

    fail_closed: bool = Field(
        default=True,
        description=(
            "On internal check errors, report a check_error finding rather than skipping it."
        ),
    )


__all__ = ["Config"]
