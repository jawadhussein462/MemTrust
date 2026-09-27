"""Correctness check framework: the "father" class for the correctness family.

::

    BaseCheck
    └── CorrectnessCheck
        ├── ContradictionCheck
        ├── DuplicationCheck
        ├── FreshnessCheck
        └── GeneralizationCheck

Correctness checks compare a candidate with what the store already holds
(``context.existing``) or with its own metadata, so they run on writes only;
the engine enforces expiry and supersession on reads itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ..base import WRITE, BaseCheck


class CorrectnessCheck(BaseCheck):
    """Base class for correctness checks (write-only, category ``correctness``)."""

    category: ClassVar[Category] = Category.CORRECTNESS
    operations = WRITE

    def finding(
        self,
        code: str,
        *,
        severity: Severity,
        action: Action,
        message: str,
        evidence: Mapping[str, object] | None = None,
    ) -> Finding:
        """Build a finding attributed to this check."""
        return Finding(
            code=code,
            category=self.category,
            severity=severity,
            message=message,
            evidence=dict(evidence or {}),
            check=self.name,
            recommended_action=action,
        )


__all__ = ["CorrectnessCheck"]
