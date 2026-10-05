"""Read-only scan sources: stream records in batches, never write.

A scan source yields :class:`~memtrust.MemoryRecord` objects. Connections
are used for listing and fetching only; ``--sample`` caps how many records
are pulled from a large store.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any, Protocol, runtime_checkable

from ..exceptions import ConfigurationError
from ..models.memory import MemoryRecord

DEFAULT_BATCH_SIZE = 500
_TEXT_KEYS = ("content", "text", "page_content", "document", "memory", "pageContent")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@runtime_checkable
class ScanSource(Protocol):
    """A read-only iterator of stored memories."""

    def records(
        self, *, batch_size: int = DEFAULT_BATCH_SIZE, sample: int | None = None
    ) -> Iterator[MemoryRecord]: ...


def take(
    items: Iterable[MemoryRecord],
    *,
    sample: int | None,
) -> Iterator[MemoryRecord]:
    """Yield records, stopping after ``sample`` if set."""
    for n, item in enumerate(items, start=1):
        yield item
        if sample is not None and n >= sample:
            return


def text_from_payload(
    content: object | None,
    metadata: object | None = None,
    *,
    field: str | None = None,
) -> str:
    """Pick a document string from a store payload."""
    meta = metadata if isinstance(metadata, dict) else {}
    if field:
        value = meta.get(field)
        if value is not None and str(value).strip():
            return str(value)
    if content is not None and str(content).strip():
        return str(content)
    for key in _TEXT_KEYS:
        value = meta.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return str(content) if content is not None else ""


def quote_ident(name: str) -> str:
    """Quote a SQL identifier (optionally ``schema.table``). Rejects injection."""
    parts = name.split(".")
    if not parts or not all(_IDENT.fullmatch(part) for part in parts):
        raise ConfigurationError(
            f"Invalid SQL identifier {name!r}: use letters, digits, and underscores."
        )
    return ".".join(f'"{part}"' for part in parts)


def missing_extra(name: str, extra: str) -> ConfigurationError:
    return ConfigurationError(f'{name} support requires `pip install "memtrust[{extra}]"`.')


def to_record(memory_id: Any, content: str) -> MemoryRecord:
    return MemoryRecord(id=str(memory_id), content=content)


__all__ = [
    "DEFAULT_BATCH_SIZE",
    "ScanSource",
    "missing_extra",
    "quote_ident",
    "take",
    "text_from_payload",
    "to_record",
]
