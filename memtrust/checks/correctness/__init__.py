"""Correctness checks: contradiction, duplication, freshness, and generalization."""

from __future__ import annotations

from .base import CorrectnessCheck
from .contradiction import ContradictionCheck
from .duplication import DuplicationCheck
from .freshness import FreshnessCheck
from .generalization import GeneralizationCheck

__all__ = [
    "ContradictionCheck",
    "CorrectnessCheck",
    "DuplicationCheck",
    "FreshnessCheck",
    "GeneralizationCheck",
]
