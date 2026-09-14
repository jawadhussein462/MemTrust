"""Example 7 — Secret detection.

Credentials that slip into a memory write are blocked, not persisted.

Run:  python examples/07_secret_detection.py
"""

from __future__ import annotations

from memtrust import MemTrust
from memtrust.backends import InMemoryBackend


def main() -> None:
    memory = MemTrust().protect(InMemoryBackend())

    result = memory.add("The billing API key is sk-abcdefghijklmnop1234567890.")
    print("allowed :", result.allowed)
    print("action  :", result.decision.action.value)
    print("stored  :", result.record)


if __name__ == "__main__":
    main()
