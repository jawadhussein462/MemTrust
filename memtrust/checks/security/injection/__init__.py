"""Injection: agent-directed instructions persisted as memory.

:class:`InjectionCheck` runs one or more detectors:

=========================  ===============================================  ==========
Detector                   Method                                           Needs
=========================  ===============================================  ==========
HeuristicInjectionDetector deobfuscation + phrase patterns (default)        nothing
PromptGuardDetector        meta-llama/Llama-Prompt-Guard-2-86M              [hf]
ProtectAIDeBERTaDetector   protectai/deberta-v3-base-prompt-injection-v2    [hf]
DeepsetDeBERTaDetector     deepset/deberta-v3-base-injection                [hf]
SentinelDetector           qualifire/prompt-injection-sentinel              [hf]
PromptShieldDetector       Azure AI Content Safety Prompt Shields           API key
LakeraGuardDetector        Lakera Guard /v2/guard                           API key
=========================  ===============================================  ==========
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
