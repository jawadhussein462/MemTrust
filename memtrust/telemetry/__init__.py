"""Observability facade.

* Uses the stdlib :mod:`logging` module and **never** calls
  ``logging.basicConfig`` — configuring logging is the application's job.
* Tracing is optional and injected (no globals): the default is a no-op
  tracer; an OpenTelemetry-backed tracer can be supplied via
  :func:`memtrust.telemetry.otel.otel_tracer`.
* Raw memory content and secrets are never placed on spans by default.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import Protocol, runtime_checkable

# Span names.
SPAN_SCAN = "memtrust.scan"

# Attribute keys (safe metadata only).
ATTR_FINDING_COUNT = "memtrust.finding_count"
ATTR_OPERATION = "memtrust.operation"


def get_logger(name: str = "memtrust") -> logging.Logger:
    """Return a library logger. The library never configures handlers."""
    return logging.getLogger(name)


@runtime_checkable
class Span(Protocol):
    def set_attribute(self, key: str, value: object) -> None: ...


@runtime_checkable
class Tracer(Protocol):
    def span(
        self, name: str, attributes: Mapping[str, object] | None = None
    ) -> AbstractContextManager[Span]: ...


class _NullSpan:
    def set_attribute(self, key: str, value: object) -> None:
        return None


class NullTracer:
    """Default tracer: does nothing, allocates nothing meaningful."""

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, object] | None = None) -> Iterator[Span]:
        yield _NullSpan()


__all__ = [
    "ATTR_FINDING_COUNT",
    "ATTR_OPERATION",
    "SPAN_SCAN",
    "NullTracer",
    "Span",
    "Tracer",
    "get_logger",
]
