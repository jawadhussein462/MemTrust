"""Scan agent memory for poisoned facts, hidden instructions, and leaked secrets.

From the command line:

    memorysec scan chroma --path ./chroma_db --collection agent_memory
    memorysec scan jsonl export.jsonl --report report.html --json findings.json

From Python, create a `MemorySec` and call `scan`. The scan reads records and
returns a `ScanReport`. It does not change the store.
"""

from __future__ import annotations

from ._version import __version__
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
    ScanError,
    ScanReport,
    Severity,
)

__all__ = [
    "Action",
    "AsyncMemorySec",
    "BackendError",
    "Category",
    "Config",
    "ConfigurationError",
    "Finding",
    "MemoryCandidate",
    "MemoryRecord",
    "MemorySec",
    "MemorySecError",
    "MemoryStatus",
    "Risk",
    "ScanError",
    "ScanReport",
    "Severity",
    "__version__",
]
