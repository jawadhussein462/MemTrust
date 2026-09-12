"""Serialize / reconstruct MemTrust records through provider metadata.

Vector stores and RAG indexes typically accept flat metadata. Adapters stash
the full record under ``memtrust`` as JSON and rebuild it on read so
status, expiry, and lineage survive the round-trip.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.memory import MemoryRecord

MT_KEY = "memtrust"


def encode_record(memory: MemoryRecord) -> dict[str, str]:
    """Flat metadata dict safe for Chroma / Qdrant / LangChain / LlamaIndex."""
    return {MT_KEY: memory.model_dump_json()}


def _parse_stored(stored: Any) -> dict[str, Any] | None:
    if isinstance(stored, dict):
        return stored
    if isinstance(stored, str):
        try:
            parsed = json.loads(stored)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def decode_record(
    *,
    memory_id: str,
    content: str,
    metadata: Any,
) -> MemoryRecord:
    """Rebuild a :class:`MemoryRecord` from provider metadata + document text."""
    stored = metadata.get(MT_KEY) if isinstance(metadata, dict) else None
    payload = _parse_stored(stored)
    if payload is not None:
        record = MemoryRecord.model_validate(payload)
        return record.model_copy(update={"id": str(memory_id)})
    return MemoryRecord(id=str(memory_id), content=content)


__all__ = ["MT_KEY", "decode_record", "encode_record"]
