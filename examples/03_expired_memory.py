"""Example 3 — Expired / stale knowledge is not returned.

Expired (and not-yet-valid) long-term memories are filtered out of protected
reads, so a stale RAG chunk cannot keep influencing the agent.

Run:  python examples/03_expired_memory.py
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from memtrust import MemoryRecord, MemTrust


def main() -> None:
    guard = MemTrust()
    now = datetime.now(UTC)

    fresh = MemoryRecord(
        id="fresh",
        content="Q3 promo code is SPRING.",
        expires_at=now + timedelta(days=30),
    )
    stale = MemoryRecord(
        id="stale",
        content="Q1 promo code was WINTER.",
        expires_at=now - timedelta(days=1),
    )

    result = guard.check_read([fresh, stale])
    print("returned :", [s.memory for s in result.results])
    for withheld in result.filtered:
        print("filtered :", withheld.record.id, "->", withheld.code)


if __name__ == "__main__":
    main()
