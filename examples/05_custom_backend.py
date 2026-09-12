"""Example 5 — Custom backend via the MemoryBackend Protocol.

Any object with add/search/get/delete works with ``protect(...)`` — no base
class or inheritance required (structural typing).

Run:  python examples/05_custom_backend.py
"""

from __future__ import annotations

from memtrust import MemoryRecord, MemTrust


class DictBackend:
    """A tiny custom backend backed by a plain dict."""

    def __init__(self) -> None:
        self._data: dict[str, MemoryRecord] = {}

    def add(self, memory: MemoryRecord) -> MemoryRecord:
        self._data[memory.id] = memory
        return memory

    def search(self, query: str, *, limit: int = 10) -> list[MemoryRecord]:
        hits = [r for r in self._data.values() if query.lower() in r.content.lower()]
        return hits[:limit]

    def get(self, memory_id: str) -> MemoryRecord | None:
        return self._data.get(memory_id)

    def delete(self, memory_id: str) -> None:
        self._data.pop(memory_id, None)


def main() -> None:
    memory = MemTrust().protect(DictBackend())

    memory.add("Customer prefers email over phone.")
    results = memory.search("email")
    for item in results:
        print(item.memory)


if __name__ == "__main__":
    main()
