"""Example 3 — Expired memory is not returned.

Expired (and not-yet-valid) memories are filtered out of protected reads.

Run:  python examples/03_expired_memory.py
"""

from __future__ import annotations

from datetime import timedelta

from memtrust import MemTrust, MemoryRecord, Scope
from memtrust._time import utcnow


def main() -> None:
    guard = MemTrust()
    now = utcnow()

    fresh = MemoryRecord(
        id="fresh",
        content="Q3 promo code is SPRING.",
        scope=Scope(tenant_id="acme"),
        expires_at=now + timedelta(days=30),
    )
    stale = MemoryRecord(
        id="stale",
        content="Q1 promo code was WINTER.",
        scope=Scope(tenant_id="acme"),
        expires_at=now - timedelta(days=1),
    )

    result = guard.check_read([fresh, stale], scope={"tenant_id": "acme"})
    print("returned :", [s.memory for s in result.results])
    for withheld in result.filtered:
        print("filtered :", withheld.record.id, "->", withheld.code)


if __name__ == "__main__":
    main()
