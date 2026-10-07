"""Poisoning: false or attacker-controlled facts planted in memory / RAG.

:class:`PoisoningCheck` runs one or more detectors:

==========================  ================================================  ==========
Detector                    Method                                            Needs
==========================  ================================================  ==========
HeuristicPoisoningDetector  control-bypass + redirect patterns (default)      nothing
FilterRAGDetector           Freq-Density of query/answer words (FilterRAG)    query
TrustRAGDetector            tight near-paraphrase cluster among neighbours    neighbours
PerplexityDetector          causal-LM perplexity (adversarial suffixes)       [hf]
==========================  ================================================  ==========
"""

from __future__ import annotations

from .check import PoisoningCheck
from .filterrag import FilterRAGDetector, freq_density
from .heuristic import HeuristicPoisoningDetector, poisoning_matches, redirect_matches
from .perplexity import PerplexityDetector
from .trustrag import TrustRAGDetector

__all__ = [
    "FilterRAGDetector",
    "HeuristicPoisoningDetector",
    "PerplexityDetector",
    "PoisoningCheck",
    "TrustRAGDetector",
    "freq_density",
    "poisoning_matches",
    "redirect_matches",
]
