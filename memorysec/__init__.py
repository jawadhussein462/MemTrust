"""MemorySec — scan agent memory for poisoned facts, hidden instructions, and leaked secrets.

memorysec scan chroma --path ./chroma_db --collection agent_memory
memorysec scan jsonl export.jsonl --report report.html --json findings.json
"""

from __future__ import annotations

from .checks.base import check
from .client import AsyncMemorySec, MemorySec
from .config import Config
from .exceptions import (
    BackendError,
    ConfigurationError,
    MemorySecError,
)
from .models import (
    Action,
    Category,
    Finding,
    MemoryCandidate,
    MemoryRecord,
    MemoryStatus,
    Risk,
    ScanReport,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "Action",
    "AsyncMemorySec",
    "BackendError",
    "Category",
    "Config",
    "ConfigurationError",
    "Finding",
    "MemorySec",
    "MemorySecError",
    "MemoryCandidate",
    "MemoryRecord",
    "MemoryStatus",
    "Risk",
    "ScanReport",
    "Severity",
    "__version__",
    "check",
]
