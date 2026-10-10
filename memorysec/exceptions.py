"""Errors MemorySec raises.

A scan returns a `ScanReport`. It does not raise because a memory looked
suspicious. These exceptions are for bad setup, a broken backend, or a
programming mistake.
"""

from __future__ import annotations


class MemorySecError(Exception):
    """Base class for every error this library raises."""


class ConfigurationError(MemorySecError):
    """The caller passed settings that cannot work.

    Raised for an empty detector list, a bad threshold, a missing API key,
    or a scan source that is not a source, a `.all()` object, or an iterable.
    """


class BackendError(MemorySecError):
    """A store or hosted API failed while MemorySec was calling it.

    The message names the URL or operation. It does not include the memory
    text that was sent.
    """


class IntegrationError(MemorySecError):
    """An optional extra is not installed or is set up wrong.

    Raised when OpenTelemetry is requested but `memorysec[otel]` is missing.
    """


class CheckError(MemorySecError):
    """A check crashed.

    The scan engine does not raise this: a crashing check or detector is
    recorded in `ScanReport.errors` and the scan is marked incomplete. It is
    kept for callers that want to raise on `not report.complete`.
    """


__all__ = [
    "BackendError",
    "CheckError",
    "ConfigurationError",
    "IntegrationError",
    "MemorySecError",
]
