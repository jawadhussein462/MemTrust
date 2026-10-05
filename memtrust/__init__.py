"""MemTrust — scan agent memory for poisoned facts, hidden instructions, and leaked secrets.

memtrust scan chroma --path ./chroma_db --collection agent_memory
memtrust scan jsonl export.jsonl --report report.html --json findings.json
"""

from __future__ import annotations

from .checks.base import check
from .client import AsyncMemTrust, MemTrust
from .config import Config
from .exceptions import (
    BackendError,
    ConfigurationError,
    MemTrustError,
)
from .models import (
    Action,
    Category,
    Decision,
    Finding,
    MemoryCandidate,
    MemoryRecord,
    MemoryRelationship,
    MemoryStatus,
    ReadResult,
    RevocationReport,
    Risk,
    SafeMemory,
    ScanReport,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "Action",
    "AsyncMemTrust",
    "BackendError",
    "Category",
    "Config",
    "ConfigurationError",
    "Decision",
    "Finding",
    "MemTrust",
    "MemTrustError",
    "MemoryCandidate",
    "MemoryRecord",
    "MemoryRelationship",
    "MemoryStatus",
    "ReadResult",
    "RevocationReport",
    "Risk",
    "SafeMemory",
    "ScanReport",
    "Severity",
    "__version__",
    "check",
]
