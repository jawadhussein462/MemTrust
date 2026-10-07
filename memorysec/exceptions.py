"""Exception hierarchy for MemorySec.

A scan returns a :class:`~memorysec.ScanReport` rather than raising.
Exceptions are reserved for programmer errors, backend failures, and
misconfiguration.
"""

from __future__ import annotations


class MemorySecError(Exception):
    """Base class for all MemorySec errors."""


class ConfigurationError(MemorySecError):
    """Invalid or contradictory configuration."""


class BackendError(MemorySecError):
    """A wrapped memory backend raised or misbehaved."""


class IntegrationError(MemorySecError):
    """An optional integration is unavailable or misconfigured."""


class CheckError(MemorySecError):
    """A check raised unexpectedly (surfaced when fail_closed is disabled)."""


__all__ = [
    "BackendError",
    "CheckError",
    "ConfigurationError",
    "IntegrationError",
    "MemorySecError",
]
