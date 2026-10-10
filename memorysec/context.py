"""The `CheckContext` handed to every check.

A check receives the memory plus this object and returns findings. It should
not change global state or do I/O. The shape is:

    (candidate, context) -> list[Finding]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .config import Config
from .models.memory import MemoryRecord


@dataclass
class CheckContext:
    """Extra facts a check may use while scanning one record.

    Attributes:
        config: Settings for this scan, including `fail_closed`.
        now: Clock time captured when the scan started.
        operation: What the engine is doing. Scans set this to `"scan"`.
        existing: The other records in this batch, when the caller passed a
            list or tuple. TrustRAG uses these as neighbours. A streaming
            scan leaves this empty.
        query: The retrieval question, when the caller passed
            `MemorySec.scan(..., query=)`. Most checks ignore it.
    """

    config: Config
    now: datetime
    operation: str = "scan"
    existing: list[MemoryRecord] = field(default_factory=list)
    query: str | None = None


__all__ = ["CheckContext"]
