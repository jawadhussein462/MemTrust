"""Settings for one `MemorySec` instance.

Pass a `Config` into the constructor. Nothing here is read from a global.
Every field has a default, so `MemorySec()` works with no arguments.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Config(BaseModel):
    """Settings a check can read while it runs.

    Attributes:
        fail_closed: When `True` (the default), a check that crashes becomes
            a `check_error` finding instead of being skipped. When `False`,
            the error is logged and that check contributes nothing.
    """

    model_config = ConfigDict(extra="forbid")

    fail_closed: bool = Field(
        default=True,
        description=(
            "On internal check errors, report a check_error finding rather than skipping it."
        ),
    )


__all__ = ["Config"]
