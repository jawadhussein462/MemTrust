"""Check framework: the :class:`MemoryCheck` protocol and helpers.

Checks form a pipeline. Each check is independent and returns a list of
findings; adding a new check never requires editing the engine. Custom
checks can be plain functions, the ``@check`` decorator, or any object
implementing the protocol. Every check runs when a store is scanned.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ..context import CheckContext
from ..exceptions import ConfigurationError
from ..models.finding import Finding
from ..models.memory import MemoryCandidate

# What a check function may return.
CheckFunction = Callable[[MemoryCandidate, CheckContext], "Finding | list[Finding] | None"]


@runtime_checkable
class MemoryCheck(Protocol):
    """A named check over a candidate memory."""

    name: str

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]: ...


class BaseCheck:
    """Convenience base class for built-in checks."""

    name: str = "base"

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        raise NotImplementedError


class FunctionCheck:
    """Adapts a plain callable into a :class:`MemoryCheck`."""

    def __init__(self, name: str, fn: CheckFunction) -> None:
        self.name = name
        self._fn = fn

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        result = self._fn(candidate, context)
        if result is None:
            return []
        if isinstance(result, Finding):
            return [result]
        return list(result)


def check(name: str) -> Callable[[CheckFunction], FunctionCheck]:
    """Decorator turning a function into a reusable check.

    Example::

        @check("no-production-passwords")
        def no_prod_passwords(candidate, context):
            if "password" in candidate.content.lower():
                return Finding(code="production_password", severity="critical",
                               category="security", message="Passwords may not be persisted.")
    """

    def decorator(fn: CheckFunction) -> FunctionCheck:
        return FunctionCheck(name, fn)

    return decorator


def normalize_check(obj: MemoryCheck | CheckFunction) -> MemoryCheck:
    """Coerce user-supplied checks (callables or objects) into MemoryCheck."""
    if hasattr(obj, "check") and hasattr(obj, "name"):
        return obj
    if callable(obj):
        name = getattr(obj, "__name__", None) or obj.__class__.__name__
        return FunctionCheck(name, obj)
    raise ConfigurationError(
        f"Object {obj!r} is not a valid check (needs .check/.name or be callable)."
    )


__all__ = [
    "BaseCheck",
    "CheckFunction",
    "FunctionCheck",
    "MemoryCheck",
    "check",
    "normalize_check",
]
