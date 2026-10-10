"""Errors Mimvo raises.

A scan returns a `ScanReport`. It does not raise because a memory looked
suspicious. These exceptions are for bad setup, a broken backend, or a
programming mistake.
"""

from __future__ import annotations


class MimvoError(Exception):
    """Base class for every error this library raises."""


class ConfigurationError(MimvoError):
    """The caller passed settings that cannot work.

    Raised for an empty detector list, a bad threshold, a missing API key,
    or a scan source that is not a source, a `.all()` object, or an iterable.
    """


class BackendError(MimvoError):
    """A store or hosted API failed while Mimvo was calling it.

    The message names the URL or operation. It does not include the memory
    text that was sent.
    """


class IntegrationError(MimvoError):
    """An optional extra is not installed or is set up wrong.

    Raised when OpenTelemetry is requested but `mimvo[otel]` is missing.
    """


class CheckError(MimvoError):
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
    "MimvoError",
]
