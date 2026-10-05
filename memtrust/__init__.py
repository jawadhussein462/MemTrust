"""MemTrust — scan agent memory for poisoned facts, hidden instructions, and leaked secrets.

Find, fix, prevent: ``memtrust scan`` finds problems, the HTML report explains
the fix, and ``protect()`` blocks new ones at write time.

    memtrust scan chroma --path ./chroma_db --collection agent_memory
    memtrust scan jsonl export.jsonl --report report.html --json findings.json --fail-on high

    from memtrust import MemTrust
    guard = MemTrust()
    memory = guard.protect(backend)
"""

from __future__ import annotations

from .checks.base import check
from .client import AsyncMemTrust, AsyncProtectedMemory, MemTrust, ProtectedMemory
from .config import Config
from .exceptions import (
    BackendError,
    ConfigurationError,
    MemTrustError,
)
from .models import (
    Action,
    AddResult,
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
    "AddResult",
    "AsyncMemTrust",
    "AsyncProtectedMemory",
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
    "ProtectedMemory",
    "ReadResult",
    "RevocationReport",
    "Risk",
    "SafeMemory",
    "ScanReport",
    "Severity",
    "__version__",
    "check",
]
