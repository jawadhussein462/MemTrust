"""Check framework: the :class:`MemoryCheck` protocol and helpers.

Checks form a pipeline (chain of responsibility). Each check is independent
and returns a list of findings; adding a new check never requires editing
the engine or ``check_write``. Custom checks can be plain functions, the
``@check`` decorator, or any object implementing the protocol.

A check runs on writes by default. Setting ``operations = ("write", "read")``
also runs it on every retrieved record, which is how content-only security
checks catch poisoned or injected documents that entered the store through
another pipeline.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol, runtime_checkable

from ..context import CheckContext
from ..exceptions import ConfigurationError
from ..models.finding import Finding
from ..models.memory import MemoryCandidate

# What a check function may return.
CheckFunction = Callable[[MemoryCandidate, CheckContext], "Finding | list[Finding] | None"]

WRITE: tuple[str, ...] = ("write",)
WRITE_AND_READ: tuple[str, ...] = ("write", "read")
_OPERATIONS = frozenset(WRITE_AND_READ)


@runtime_checkable
class MemoryCheck(Protocol):
    """A named check over a candidate memory.

    Optionally declares ``operations`` (default ``("write",)``).
    """

    name: str

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]: ...


def check_operations(chk: object) -> tuple[str, ...]:
    """The operations a check runs on (``("write",)`` unless it says otherwise)."""
    ops = getattr(chk, "operations", None)
    return tuple(ops) if ops else WRITE


class BaseCheck:
    """Convenience base class for built-in checks."""

    name: str = "base"
    operations: tuple[str, ...] = WRITE

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        raise NotImplementedError


class FunctionCheck:
    """Adapts a plain callable into a :class:`MemoryCheck`."""

    def __init__(self, name: str, fn: CheckFunction, *, on: Iterable[str] = WRITE) -> None:
        operations = tuple(on)
        unknown = set(operations) - _OPERATIONS
        if unknown or not operations:
            raise ConfigurationError(
                f"Check {name!r}: 'on' must name 'write' and/or 'read', got {operations!r}."
            )
        self.name = name
        self.operations = operations
        self._fn = fn

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        result = self._fn(candidate, context)
        if result is None:
            return []
        if isinstance(result, Finding):
            return [result]
        return list(result)


def check(name: str, *, on: Iterable[str] = WRITE) -> Callable[[CheckFunction], FunctionCheck]:
    """Decorator turning a function into a reusable check.

    ``on=("write", "read")`` also runs it on retrieved records
    (``context.operation`` tells the two apart).

    Example::

        @check("no-production-passwords")
        def no_prod_passwords(candidate, context):
            if "password" in candidate.content.lower():
                return Finding(code="production_password", severity="critical",
                               category="security", message="Passwords may not be persisted.")
    """

    def decorator(fn: CheckFunction) -> FunctionCheck:
        return FunctionCheck(name, fn, on=on)

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
    "WRITE",
    "WRITE_AND_READ",
    "BaseCheck",
    "CheckFunction",
    "FunctionCheck",
    "MemoryCheck",
    "check",
    "check_operations",
    "normalize_check",
]
