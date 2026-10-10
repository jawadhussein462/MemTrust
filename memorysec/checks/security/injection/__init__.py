"""Injection: instructions aimed at the agent that were saved as memory.

`InjectionCheck` runs one or more detectors:

* `HeuristicInjectionDetector` — phrase patterns after deobfuscation. Default.
  Needs nothing extra.
* `PromptGuardDetector` — `meta-llama/Llama-Prompt-Guard-2-86M`. Needs `[hf]`.
* `ProtectAIDeBERTaDetector` — Protect AI DeBERTa v2. Needs `[hf]`.
* `DeepsetDeBERTaDetector` — deepset DeBERTa. Needs `[hf]`.
* `SentinelDetector` — Qualifire Sentinel. Needs `[hf]`.
* `PromptShieldDetector` — Azure Prompt Shields. Needs an API key.
* `LakeraGuardDetector` — Lakera Guard. Needs an API key.
"""

from __future__ import annotations

from .check import InjectionCheck
from .deepset_deberta import DeepsetDeBERTaDetector
from .heuristic import HeuristicInjectionDetector, injection_matches
from .lakera_guard import LakeraGuardDetector
from .prompt_guard import PromptGuardDetector
from .prompt_shield import PromptShieldDetector
from .protectai_deberta import ProtectAIDeBERTaDetector
from .sentinel import SentinelDetector

__all__ = [
    "DeepsetDeBERTaDetector",
    "HeuristicInjectionDetector",
    "InjectionCheck",
    "LakeraGuardDetector",
    "PromptGuardDetector",
    "PromptShieldDetector",
    "ProtectAIDeBERTaDetector",
    "SentinelDetector",
    "injection_matches",
]
