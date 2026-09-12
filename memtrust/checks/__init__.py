"""Built-in checks and the check framework.

``default_checks()`` returns the standard pipeline. Additional checks can be
appended without modifying the engine.
"""

from __future__ import annotations

from .authority import AuthorityCheck
from .base import (
    BaseCheck,
    CheckFunction,
    FunctionCheck,
    MemoryCheck,
    check,
    normalize_check,
)
from .contradiction import ContradictionCheck
from .duplication import DuplicationCheck
from .freshness import FreshnessCheck
from .generalization import GeneralizationCheck
from .injection import InjectionCheck
from .scope import ScopeCheck
from .secrets import SecretsCheck
from .tenant import TenantCheck


def default_checks() -> list[MemoryCheck]:
    """The default write-check pipeline, in execution order."""
    return [
        SecretsCheck(),
        InjectionCheck(),
        TenantCheck(),
        ScopeCheck(),
        AuthorityCheck(),
        FreshnessCheck(),
        DuplicationCheck(),
        ContradictionCheck(),
        GeneralizationCheck(),
    ]


__all__ = [
    "AuthorityCheck",
    "BaseCheck",
    "CheckFunction",
    "ContradictionCheck",
    "DuplicationCheck",
    "FreshnessCheck",
    "FunctionCheck",
    "GeneralizationCheck",
    "InjectionCheck",
    "MemoryCheck",
    "ScopeCheck",
    "SecretsCheck",
    "TenantCheck",
    "check",
    "default_checks",
    "normalize_check",
]
