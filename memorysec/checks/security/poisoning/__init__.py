"""Poisoning: false or attacker-controlled facts planted in memory or RAG.

`PoisoningCheck` runs one or more detectors:

* `HeuristicPoisoningDetector` — phrases that turn off a control, or that
  redirect payments and data. Default. Needs nothing extra.
* `TrustRAGDetector` — a tight cluster of near-copies among neighbouring
  records. Needs those neighbours from a batched scan.
* `PerplexityDetector` — text a language model finds implausible, which
  catches adversarial suffixes. Needs `[hf]`.
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
