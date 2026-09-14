"""MemTrust — security and correctness for agent long-term memory.

A vendor-neutral trust boundary that sits between an agent and its knowledge
memory (RAG corpora, user long-term facts, retrieved documents) and answers:
should this be written? should this be returned? why?

Simple API on top, two families of checks underneath::

    from memtrust import MemTrust

    guard = MemTrust()
    decision = guard.check_write("...")
    if not decision.allowed:
        print(decision.reason)

**Security** detects poisoning, injection, and secrets.
**Correctness** detects contradictions, duplicates, and stale facts.

Advanced functionality lives under discoverable namespaces:
``memtrust.checks``, ``memtrust.backends``, ``memtrust.integrations``,
``memtrust.telemetry``.
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
    "Severity",
    "__version__",
    "check",
]
