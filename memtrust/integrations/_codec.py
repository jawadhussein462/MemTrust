"""Record-state codec shared by adapters that store text and metadata separately.

Vector stores keep the document text natively. MemTrust's lifecycle state
(status, validity window, lineage, caller metadata) must travel with it,
otherwise every record comes back ``ACTIVE`` and read enforcement cannot
withhold quarantined, superseded, or revoked memories. The state is stored
as one JSON string under :data:`STATE_KEY` — a flat scalar every store
accepts as metadata/payload.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ..models.enums import MemoryStatus
from ..models.memory import MemoryRecord
from ..telemetry import get_logger

STATE_KEY = "memtrust"

_logger = get_logger(__name__)
# The store already holds id and text; the state carries everything else.
_STORE_FIELDS = frozenset({"id", "content"})
_FIELDS = frozenset(MemoryRecord.model_fields) - _STORE_FIELDS


def encode_state(record: MemoryRecord) -> str:
    """Serialize everything but the id and content."""
    return record.model_dump_json(exclude=set(_STORE_FIELDS))


def state_metadata(record: MemoryRecord) -> dict[str, str]:
    """Metadata/payload dict carrying the encoded state."""
    return {STATE_KEY: encode_state(record)}


def decode_record(metadata: Any, *, id: str, content: str) -> MemoryRecord:
    """Rebuild a record from store metadata; ``id`` and ``content`` come from the store.

    * No MemTrust state: the item was written outside MemTrust and is
      returned as an ``ACTIVE`` record (read-time checks still apply).
    * State present but unreadable: fail closed as ``QUARANTINED``, so a
      corrupted record cannot resurface as active.
    """
    raw = metadata.get(STATE_KEY) if isinstance(metadata, Mapping) else None
    if raw is None:
        return MemoryRecord(id=id, content=content)
    state = _parse(raw)
    if state is not None:
        # Unknown keys are dropped so records written by newer versions still load.
        known = {k: v for k, v in state.items() if k in _FIELDS}
        try:
            return MemoryRecord.model_validate({**known, "id": id, "content": content})
        except ValueError:
            pass
    _logger.warning("unreadable MemTrust state on record %r; treating as quarantined", id)
    return MemoryRecord(id=id, content=content, status=MemoryStatus.QUARANTINED)


def _parse(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


__all__ = ["STATE_KEY", "decode_record", "encode_state", "state_metadata"]
