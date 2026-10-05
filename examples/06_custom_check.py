"""Example 6 — Custom check with the @check decorator.

Custom checks are just functions. They run during a scan, alongside the
built-in pipeline.

Run:  python examples/06_custom_check.py
"""

from __future__ import annotations

from memtrust import Finding, MemTrust, check


@check("no-passwords")
def no_passwords(candidate, context):
    if "password" in candidate.content.lower():
        return Finding(
            code="production_password",
            severity="critical",
            category="security",
            message="Passwords may not be persisted.",
        )
    return None


def main() -> None:
    guard = MemTrust(checks=[no_passwords])
    report = guard.scan(
        [{"id": "leak", "content": "The database password is hunter2, keep it handy."}]
    )
    print(report)


if __name__ == "__main__":
    main()
