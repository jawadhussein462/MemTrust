"""JSON Lines export: one object with a ``content`` string per line."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from ..exceptions import ConfigurationError
from ..models.memory import MemoryRecord
from .source import DEFAULT_BATCH_SIZE, take, to_record


class JsonlScanSource:
    """Stream records from a JSON Lines file or an open text stream."""

    def __init__(self, path: str | Path | IO[str]) -> None:
        self._path = path

    def records(
        self, *, batch_size: int = DEFAULT_BATCH_SIZE, sample: int | None = None
    ) -> Iterator[MemoryRecord]:
        del batch_size  # lines are already streamed
        stream = self._path
        if isinstance(stream, str | Path):
            with open(stream, encoding="utf-8") as fh:
                yield from take(_iter_jsonl(fh), sample=sample)
            return
        yield from take(_iter_jsonl(stream), sample=sample)


def _iter_jsonl(stream: IO[str]) -> Iterator[MemoryRecord]:
    for lineno, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            item: Any = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"line {lineno}: invalid JSON ({exc.msg})") from exc
        if not isinstance(item, dict) or not isinstance(item.get("content"), str):
            raise ConfigurationError(f"line {lineno}: expected an object with a 'content' string")
        yield to_record(item.get("id") or f"line_{lineno}", item["content"])


__all__ = ["JsonlScanSource"]
