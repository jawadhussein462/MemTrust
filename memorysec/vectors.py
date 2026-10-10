"""Nearest-neighbour helpers over stored embeddings.

Corpus detectors (TrustRAG, hubness, NLI, embedding consistency) should use
the store's vectors and a k-NN lookup, not pairwise Python string similarity.
These functions are the shared primitive. They do not talk to a store; the
caller already loaded the records.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models.enums import MemoryStatus
from .models.memory import MemoryRecord
from .text import cosine


def as_floats(value: object) -> list[float] | None:
    """Turn a store vector into a Python list of floats.

    Args:
        value: A list or tuple of numbers, or an array with `.tolist()`.
            `None` and empty sequences become `None`.

    Returns:
        The values as `float`, or `None` when `value` is missing or not a
        sequence of numbers.
    """
    if value is None:
        return None
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, dict):
        first = next(iter(value.values()), None)
        return as_floats(first)
    if not isinstance(value, list | tuple):
        return None
    try:
        out = [float(x) for x in value]
    except (TypeError, ValueError):
        return None
    return out or None


def with_embeddings(
    records: Sequence[MemoryRecord],
    *,
    active_only: bool = True,
) -> list[MemoryRecord]:
    """Return records that carry a usable embedding.

    Args:
        records: Stored memories, possibly mixed.
        active_only: When `True` (the default), drop revoked and quarantined
            records.

    Returns:
        Records whose `embedding` is a non-empty list.
    """
    out: list[MemoryRecord] = []
    for record in records:
        if active_only and record.status != MemoryStatus.ACTIVE:
            continue
        if record.embedding:
            out.append(record)
    return out


def nearest(
    query: Sequence[float],
    records: Sequence[MemoryRecord],
    *,
    k: int,
    exclude_id: str | None = None,
    active_only: bool = True,
) -> list[tuple[MemoryRecord, float]]:
    """Return the `k` nearest records to `query` by cosine similarity.

    Args:
        query: Query vector. Usually the candidate's stored embedding.
        records: Corpus to search. Records without embeddings are skipped.
        k: Maximum number of neighbours to return. Values below 1 yield
            an empty list.
        exclude_id: Record id to skip, typically the candidate itself.
        active_only: When `True`, skip revoked and quarantined records.

    Returns:
        `(record, cosine)` pairs, highest similarity first. Shorter than
        `k` when fewer eligible records exist.
    """
    if k < 1:
        return []
    ranked: list[tuple[MemoryRecord, float]] = []
    query_list = list(query)
    for record in with_embeddings(records, active_only=active_only):
        if exclude_id is not None and record.id == exclude_id:
            continue
        assert record.embedding is not None
        try:
            score = cosine(query_list, record.embedding)
        except ValueError:
            continue
        ranked.append((record, score))
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked[:k]


def k_occurrence(
    records: Sequence[MemoryRecord],
    *,
    k: int = 10,
    active_only: bool = True,
) -> dict[str, int]:
    """Count how often each record appears in the others' `k` nearest neighbours.

    A point that is a neighbour of many others is a hub. Poison written to
    be retrieved for many queries tends to become one (Radovanović et al.,
    JMLR 2010). The mean count is `k` when every record has an embedding.

    Args:
        records: Corpus. Records without embeddings are ignored.
        k: Neighbourhood size used for each record.
        active_only: When `True`, skip revoked and quarantined records.

    Returns:
        `{record_id: count}` for every record that had an embedding.
        Missing ids were skipped.
    """
    indexed = with_embeddings(records, active_only=active_only)
    counts = {record.id: 0 for record in indexed}
    for record in indexed:
        assert record.embedding is not None
        for neighbour, _score in nearest(
            record.embedding,
            indexed,
            k=k,
            exclude_id=record.id,
            active_only=False,
        ):
            counts[neighbour.id] = counts.get(neighbour.id, 0) + 1
    return counts


__all__ = [
    "as_floats",
    "k_occurrence",
    "nearest",
    "with_embeddings",
]
