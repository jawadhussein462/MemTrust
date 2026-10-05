"""Custom checks: decorator, plain callables, normalization, fail modes."""

from __future__ import annotations

import pytest

from memtrust import Finding, MemTrust, check
from memtrust.checks.base import FunctionCheck, normalize_check
from memtrust.exceptions import ConfigurationError


@check("no-passwords")
def no_passwords(candidate, context):
    if "password" in candidate.content.lower():
        return Finding(
            code="production_password",
            severity="critical",
            category="security",
            message="No passwords.",
        )
    return None


def _types(guard: MemTrust, text: str) -> set[str]:
    report = guard.scan([{"id": "m", "content": text}])
    return {f.type for f in report.findings}


def test_decorator_check_flags_password():
    guard = MemTrust(checks=[no_passwords])
    assert "production_password" in _types(guard, "the password is x")


def test_plain_callable_is_normalized():
    def my_check(candidate, context):
        return Finding(code="c", severity="low", category="security", message="m")

    normalized = normalize_check(my_check)
    assert normalized.name == "my_check"
    guard = MemTrust(checks=[my_check])
    assert "c" in _types(guard, "hi")


def test_function_check_handles_list_and_none():
    fc = FunctionCheck(
        "multi",
        lambda c, ctx: [Finding(code="a", message="a"), Finding(code="b", message="b")],
    )
    out = fc.check(None, None)  # type: ignore[arg-type]
    assert {f.code for f in out} == {"a", "b"}


def test_normalize_check_rejects_non_check():
    with pytest.raises(ConfigurationError):
        normalize_check(42)  # type: ignore[arg-type]


def test_fail_closed_reports_check_error():
    def boom(candidate, context):
        raise RuntimeError("kaboom")

    guard = MemTrust(checks=[boom], fail_closed=True)
    assert "check_error" in _types(guard, "hi")


def test_fail_open_ignores_check_error():
    def boom(candidate, context):
        raise RuntimeError("kaboom")

    guard = MemTrust(checks=[boom], fail_closed=False)
    assert "check_error" not in _types(guard, "hi")
