"""Exception hierarchy for MemTrust.

The common path (``check_write`` / ``check_read``) returns structured
:class:`~memtrust.Decision` / :class:`~memtrust.ReadResult` objects rather
than raising. Exceptions are reserved for programmer errors, backend
failures, and fail-closed enforcement.
"""

from __future__ import annotations


class MemTrustError(Exception):
    """Base class for all MemTrust errors."""


class ConfigurationError(MemTrustError):
    """Invalid or contradictory configuration."""


class BackendError(MemTrustError):
    """A wrapped memory backend raised or misbehaved."""


class IntegrationError(MemTrustError):
    """An optional integration is unavailable or misconfigured."""


class CheckError(MemTrustError):
    """A check raised unexpectedly (surfaced when fail_closed is disabled)."""


__all__ = [
    "BackendError",
    "CheckError",
    "ConfigurationError",
    "IntegrationError",
    "MemTrustError",
]
