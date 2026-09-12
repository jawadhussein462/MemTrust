"""Example 6 — Custom check with the @check decorator.

Custom checks are just functions. They compose with the built-in pipeline.

Run:  python examples/06_custom_check.py
"""

from __future__ import annotations

from memtrust import Finding, MemTrust, check


@check("no-production-passwords")
def no_prod_passwords(candidate, context):
    if candidate.scope.namespace == "production" and "password" in candidate.content.lower():
        return Finding(
            code="production_password",
            severity="critical",
            category="security",
            message="Production passwords may not be persisted.",
        )
    return None


def main() -> None:
    guard = MemTrust(checks=[no_prod_passwords])

    decision = guard.check_write(
        "The database password is hunter2, keep it handy.",
        source={"type": "conversation", "trust": "agent"},
        scope={"tenant_id": "acme", "namespace": "production"},
    )
    print(decision)


if __name__ == "__main__":
    main()
