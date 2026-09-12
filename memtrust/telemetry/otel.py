"""Optional OpenTelemetry-backed tracer.

Requires ``pip install "memtrust[otel]"``. Inject the result into a MemTrust
instance via ``MemTrust(tracer=otel_tracer())``.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from ..exceptions import IntegrationError
from . import Span, Tracer


class OtelTracer:
    """Adapts an OpenTelemetry tracer to the MemTrust :class:`Tracer` protocol."""

    def __init__(self, tracer: object | None = None) -> None:
        try:
            from opentelemetry import trace
        except ImportError as exc:  # pragma: no cover - only without the extra
            raise IntegrationError(
                "opentelemetry is not installed. Install with: pip install 'memtrust[otel]'"
            ) from exc
        self._tracer = tracer if tracer is not None else trace.get_tracer("memtrust")

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, object] | None = None) -> Iterator[Span]:
        with self._tracer.start_as_current_span(name) as span:  # type: ignore[union-attr]
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            yield span


def otel_tracer(tracer: object | None = None) -> Tracer:
    """Return a MemTrust-compatible tracer backed by OpenTelemetry."""
    return OtelTracer(tracer)


__all__ = ["OtelTracer", "otel_tracer"]
