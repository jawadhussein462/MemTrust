"""Observability facade.

* Logs with `loguru`. MemorySec does not add or remove sinks — configuring
  loguru is the application's job.
* Tracing is optional and injected (no globals): the default is a no-op
  tracer; an OpenTelemetry-backed tracer can be supplied via
  :func:`memorysec.telemetry.otel.otel_tracer`.
* Raw memory content and secrets are never placed on spans by default.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from loguru import logger

if TYPE_CHECKING:
    from loguru import Logger

# Span names.
SPAN_SCAN = "memorysec.scan"

# Attribute keys (safe metadata only).
ATTR_FINDING_COUNT = "memorysec.finding_count"
ATTR_OPERATION = "memorysec.operation"


def get_logger(name: str = "memorysec") -> Logger:
    """Return a loguru logger bound to ``name``. The library never adds sinks."""
    return logger.bind(name=name)


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
