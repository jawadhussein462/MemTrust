"""Read-only scan sources: stream records in batches, never write.

A scan source yields `MemoryRecord` objects. The connection is used to list
and fetch only. `sample` stops the scan after that many records, which is
how `--sample` caps a large store.
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
    """A read-only iterator of stored memories.

    Implementations must not insert, update, or delete.
    """

    def records(
        self, *, batch_size: int = DEFAULT_BATCH_SIZE, sample: int | None = None
    ) -> Iterator[MemoryRecord]:
        """Yield stored memories, one batch of fetches at a time.

        Args:
            batch_size: How many records to ask the store for per round trip.
                Default is `DEFAULT_BATCH_SIZE` (500).
            sample: Stop after this many records. `None` means read until
                the store is exhausted.

        Returns:
            An iterator of `MemoryRecord`. It may perform I/O as you pull
            from it.
        """
        ...


def take(
    items: Iterable[MemoryRecord],
    *,
    sample: int | None,
) -> Iterator[MemoryRecord]:
    """Yield records, stopping early when `sample` is set.

    Args:
        items: Records already being streamed from a store.
        sample: Maximum number to yield. `None` yields every item.

    Returns:
        An iterator. It stops after `sample` records, or when `items` ends.
    """
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
    """Pick the document string out of a store payload.

    Args:
        content: The store's document field, when it has one separate from
            metadata.
        metadata: A dict of extra fields, or anything else (ignored if it
            is not a dict).
        field: Metadata key to prefer, such as `"text"`. When that key is
            missing or blank, the function tries `content`, then the keys
            `content`, `text`, `page_content`, `document`, `memory`, and
            `pageContent`.

    Returns:
        The first non-blank string found. An empty string when every
        candidate is missing or blank and `content` itself is `None`.
    """
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
    """Quote a SQL identifier so it can be interpolated into a query.

    Args:
        name: A column, table, or `schema.table`. Each part may contain
            letters, digits, and underscores, and must not start with a digit.

    Returns:
        The name with each part wrapped in double quotes, such as
        `"public"."memories"`.

    Raises:
        ConfigurationError: A part contains anything else. That rejects
            quote tricks and statement separators.
    """
    parts = name.split(".")
    if not parts or not all(_IDENT.fullmatch(part) for part in parts):
        raise ConfigurationError(
            f"Invalid SQL identifier {name!r}: use letters, digits, and underscores."
        )
    return ".".join(f'"{part}"' for part in parts)


def missing_extra(name: str, extra: str) -> ConfigurationError:
    """Build the error raised when an optional store client is not installed.

    Args:
        name: Store name shown to the user, such as `"Chroma"`.
        extra: The pip extra, such as `"chroma"`.

    Returns:
        A `ConfigurationError` whose message is
        `pip install "memorysec[<extra>]"`. The caller raises it.
    """
    return ConfigurationError(f'{name} support requires `pip install "memorysec[{extra}]"`.')


def to_record(memory_id: Any, content: str) -> MemoryRecord:
    """Build a `MemoryRecord` from a store id and a text string.

    Args:
        memory_id: Whatever the store uses as an id. It is converted with
            `str`.
        content: The memory text.

    Returns:
        A record with status `active` and timestamps set to now.
    """
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
