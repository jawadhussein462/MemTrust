"""Example 4 — Superseding an outdated fact (history preserved).

"Alice works at Stripe" then "Alice now works at Anthropic" should SUPERSEDE
the old fact rather than blindly contradict it. The old record is marked
superseded (not deleted) and no longer surfaces in reads.

Run:  python examples/04_supersede_outdated_fact.py
"""

from __future__ import annotations

from memtrust import MemTrust
from memtrust.backends import InMemoryBackend


def main() -> None:
    memory = MemTrust().protect(InMemoryBackend())
    scope = {"tenant_id": "acme", "user_id": "alice"}
    src = {"type": "conversation", "trust": "user"}

    first = memory.add("Alice works at Stripe.", source=src, scope=scope)
    print("first add :", first.decision.action.value, "->", first.record.id)

    second = memory.add("Alice now works at Anthropic.", source=src, scope=scope)
    print("second add:", second.decision.action.value, "supersedes", second.decision.supersedes)

    current = memory.search("where does alice work", scope=scope)
    print("current   :", [s.memory for s in current])


if __name__ == "__main__":
    main()
