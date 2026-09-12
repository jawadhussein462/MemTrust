"""Pydantic-style coercion of loose inputs into domain models.

Lets callers pass plain dicts for ``source`` / ``scope`` and either a string
or a :class:`MemoryCandidate` for content, so the common case stays terse.
"""

from __future__ import annotations

from .config import Config
from .exceptions import ConfigurationError
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import SafeMemory
from .models.scope import Scope
from .models.source import Source


def coerce_source(source: Source | dict | None, config: Config) -> Source:
    if source is None:
        return Source(type="unspecified", trust=config.default_source_trust)
    if isinstance(source, Source):
        return source
    if isinstance(source, dict):
        return Source.model_validate(source)
    raise ConfigurationError(f"Cannot interpret source: {source!r}")


def coerce_scope(scope: Scope | dict | None) -> Scope:
    if scope is None:
        return Scope()
    if isinstance(scope, Scope):
        return scope
    if isinstance(scope, dict):
        return Scope.model_validate(scope)
    raise ConfigurationError(f"Cannot interpret scope: {scope!r}")


def coerce_candidate(
    content: str | MemoryCandidate | dict,
    *,
    source: Source | dict | None,
    scope: Scope | dict | None,
    config: Config,
) -> tuple[MemoryCandidate, Scope]:
    """Return ``(candidate, request_scope)``.

    ``request_scope`` may differ from ``candidate.scope`` when a caller passes
    a pre-built candidate together with an explicit request scope (used to
    detect cross-tenant writes).
    """
    if isinstance(content, MemoryCandidate):
        request_scope = coerce_scope(scope) if scope is not None else content.scope
        return content, request_scope
    if isinstance(content, dict):
        candidate = MemoryCandidate.model_validate(content)
        request_scope = coerce_scope(scope) if scope is not None else candidate.scope
        return candidate, request_scope
    if isinstance(content, str):
        candidate = MemoryCandidate(
            content=content,
            source=coerce_source(source, config),
            scope=coerce_scope(scope),
        )
        return candidate, candidate.scope
    raise ConfigurationError(f"Cannot interpret content: {content!r}")


def coerce_records(records: list) -> list[MemoryRecord]:
    out: list[MemoryRecord] = []
    for item in records:
        if isinstance(item, MemoryRecord):
            out.append(item)
        elif isinstance(item, SafeMemory):
            out.append(item.record)
        elif isinstance(item, dict):
            out.append(MemoryRecord.model_validate(item))
        else:
            raise ConfigurationError(f"Cannot interpret record: {item!r}")
    return out


__all__ = ["coerce_candidate", "coerce_records", "coerce_scope", "coerce_source"]
