"""Example 2 — Cross-tenant read isolation.

A memory owned by tenant 'acme' must never be returned to a 'globex' agent.
This is enforced in the core engine, so it holds even with a custom check
list.

Run:  python examples/02_cross_tenant_read.py
"""

from __future__ import annotations

from memtrust import MemTrust, MemoryRecord, Scope


def main() -> None:
    guard = MemTrust()

    acme_memory = MemoryRecord(
        id="mem_1",
        content="ACME acquisition target is BidCo.",
        scope=Scope(tenant_id="acme"),
    )

    result = guard.check_read([acme_memory], scope={"tenant_id": "globex"})

    print("returned to globex :", [s.memory for s in result.results])
    for withheld in result.filtered:
        print("filtered           :", withheld.record.id, "->", withheld.code, "-", withheld.reason)

    # Same tenant can read it.
    ok = guard.check_read([acme_memory], scope={"tenant_id": "acme"})
    print("returned to acme   :", [s.memory for s in ok.results])


if __name__ == "__main__":
    main()
