"""Correctness checks: contradiction, duplication, freshness, and generalization."""

from __future__ import annotations

from .contradiction import ContradictionCheck
from .duplication import DuplicationCheck
from .freshness import FreshnessCheck
from .generalization import GeneralizationCheck

__all__ = [
    "ContradictionCheck",
    "DuplicationCheck",
    "FreshnessCheck",
    "GeneralizationCheck",
]
