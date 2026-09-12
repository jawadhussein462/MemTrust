"""MemTrust — security, correctness, and governance for AI-agent memory.

A vendor-neutral trust boundary that sits between an agent and its memory
backend and answers: should this be written? should this be returned? why
does the agent believe this?

Simple API on top, rigorous trust model underneath::

    from memtrust import MemTrust

    guard = MemTrust()
    decision = guard.check_write("...", source={...}, scope={...})
    if not decision.allowed:
        print(decision.reason)

Advanced functionality lives under discoverable namespaces:
``memtrust.policies``, ``memtrust.checks``, ``memtrust.backends``,
``memtrust.integrations``, ``memtrust.semantic``, ``memtrust.audit``,
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
    TenantIsolationError,
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
    Mode,
    Policy,
    Provenance,
    ReadResult,
    Risk,
    RevocationReport,
    SafeMemory,
    Scope,
    Severity,
    Source,
    TrustLevel,
)

__version__ = "0.1.0"

__all__ = [
    # Primary entry points
    "MemTrust",
    "AsyncMemTrust",
    # Core models most users touch
    "MemoryCandidate",
    "MemoryRecord",
    "Source",
    "Scope",
    "Decision",
    "Finding",
    "Provenance",
    # Custom checks
    "check",
    # Structured results
    "ReadResult",
    "AddResult",
    "SafeMemory",
    "RevocationReport",
    # Enums
    "TrustLevel",
    "Severity",
    "Category",
    "Action",
    "Mode",
    "Risk",
    "MemoryStatus",
    "MemoryRelationship",
    # Config + protected wrappers
    "Config",
    "ProtectedMemory",
    "AsyncProtectedMemory",
    "Policy",
    # Exceptions
    "MemTrustError",
    "ConfigurationError",
    "BackendError",
    "TenantIsolationError",
    "__version__",
]
