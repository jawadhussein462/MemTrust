"""Poisoning: false or attacker-controlled facts planted in memory / RAG.

:class:`PoisoningCheck` runs one or more detectors:

==========================  ================================================  ==========
Detector                    Method                                            Needs
==========================  ================================================  ==========
HeuristicPoisoningDetector  control-bypass + redirect patterns (default)      nothing
TrustRAGDetector            tight near-paraphrase cluster among neighbours    neighbours
PerplexityDetector          causal-LM perplexity (adversarial suffixes)       [hf]
==========================  ================================================  ==========
"""

from __future__ import annotations

from .check import PoisoningCheck
from .heuristic import HeuristicPoisoningDetector, poisoning_matches, redirect_matches
from .perplexity import PerplexityDetector
from .trustrag import TrustRAGDetector

__all__ = [
    "HeuristicPoisoningDetector",
    "PerplexityDetector",
    "PoisoningCheck",
    "TrustRAGDetector",
    "poisoning_matches",
    "redirect_matches",
]
