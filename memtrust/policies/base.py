"""Policy callable type and normalization.

Policies come in two forms: declarative :class:`~memtrust.Policy` objects for
simple ``when``/``require`` rules, and plain Python callables for anything
that needs real logic. We deliberately avoid a bespoke policy DSL.
"""

from __future__ import annotations

from collections.abc import Callable

from ..context import CheckContext
from ..models.finding import Finding
from ..models.memory import MemoryCandidate

PolicyCallable = Callable[[MemoryCandidate, CheckContext], "Finding | list[Finding] | None"]


def is_policy_callable(obj: object) -> bool:
    return callable(obj) and not hasattr(obj, "when")


__all__ = ["PolicyCallable", "is_policy_callable"]
