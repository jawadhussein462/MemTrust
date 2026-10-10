"""Settings for one `MemorySec` instance.

Pass a `Config` into the constructor. Nothing here is read from a global.
Every field has a default, so `MemorySec()` works with no arguments.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Config(BaseModel):
    """Settings a check can read while it runs.

    Attributes:
        fail_closed: What an incomplete scan means. A check or detector that
            raises (missing model, network error, bad API key) is always
            logged and listed in `ScanReport.errors`, and never becomes a
            finding. With `True` (the default) that incompleteness counts as
            a failure: the CLI exits `2`, `WriteGuard` refuses the write, and
            `RetrieveGuard` drops the record. With `False` the parts that ran
            are trusted on their own.
    """

    model_config = ConfigDict(extra="forbid")

    fail_closed: bool = Field(
        default=True,
        description=(
            "Treat an incomplete scan (a check or detector raised) as a failure: "
            "the CLI exits 2 and the guards block the affected records."
        ),
    )


__all__ = ["Config"]
