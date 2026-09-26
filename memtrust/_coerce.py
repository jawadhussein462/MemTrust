"""Pydantic-style coercion of loose inputs into domain models.

Lets callers pass a string, a dict, or a :class:`MemoryCandidate` for content
so the common case stays terse.
"""

from __future__ import annotations

from .exceptions import ConfigurationError
from .models.memory import MemoryCandidate, MemoryRecord
from .models.results import SafeMemory


def coerce_candidate(content: str | MemoryCandidate | dict) -> MemoryCandidate:
    """Return a :class:`MemoryCandidate` from a string, dict, or model."""
    if isinstance(content, MemoryCandidate):
        return content
    if isinstance(content, dict):
        return MemoryCandidate.model_validate(content)
    if isinstance(content, str):
        return MemoryCandidate(content=content)
    raise ConfigurationError(f"Cannot interpret content: {content!r}")


def coerce_record(item: object) -> MemoryRecord:
    """Return a :class:`MemoryRecord` from a record, a :class:`SafeMemory`, or a dict."""
    if isinstance(item, MemoryRecord):
        return item
    if isinstance(item, SafeMemory):
        return item.record
    if isinstance(item, dict):
        return MemoryRecord.model_validate(item)
    raise ConfigurationError(f"Cannot interpret record: {item!r}")


def coerce_records(records: list) -> list[MemoryRecord]:
    return [coerce_record(item) for item in records]


__all__ = ["coerce_candidate", "coerce_record", "coerce_records"]
