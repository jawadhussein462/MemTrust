"""Example 7 — Scan for leaked secrets.

A JSONL export of agent memory is screened locally. Secret values never
appear in the report.

Run:  python examples/07_secret_detection.py
CLI:  memtrust scan jsonl export.jsonl --report report.html
"""

from __future__ import annotations

from memtrust import MemoryRecord, MemTrust


def main() -> None:
    records = [
        MemoryRecord(id="ok", content="Alice prefers annual billing."),
        MemoryRecord(id="leak", content="The billing API key is sk-abcdefghijklmnop1234567890."),
    ]
    report = MemTrust().scan(records)
    print(report)
    for finding in report.findings:
        print(finding.id, finding.type, finding.action.value, finding.snippet)


if __name__ == "__main__":
    main()
