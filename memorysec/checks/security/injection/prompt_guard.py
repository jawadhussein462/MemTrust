"""Meta Llama Prompt Guard 2 (``meta-llama/Llama-Prompt-Guard-2-86M``).

A BERT-style classifier that labels text ``BENIGN`` or ``MALICIOUS``, where
malicious means an explicit attempt to override prior instructions -- exactly
the persistent-instruction pattern MemorySec screens memories for. The 86M
model (mDeBERTa-base) handles non-English text; ``Llama-Prompt-Guard-2-22M``
(DeBERTa-xsmall) is faster and English-focused. Both are gated on the Hub
and have a 512-token window, so long content is scanned in chunks.

    pip install "memorysec[hf]"
    InjectionCheck(detectors=[HeuristicInjectionDetector(), PromptGuardDetector()])
"""

from __future__ import annotations

from .._hf import HFTextClassifierDetector

PROMPT_GUARD_2_86M = "meta-llama/Llama-Prompt-Guard-2-86M"
PROMPT_GUARD_2_22M = "meta-llama/Llama-Prompt-Guard-2-22M"


class PromptGuardDetector(HFTextClassifierDetector):
    """Llama Prompt Guard 2 sequence classifier (``MALICIOUS`` = injection)."""

    name = "prompt_guard"
    model_id = PROMPT_GUARD_2_86M
    positive_labels = frozenset({"MALICIOUS", "INJECTION", "JAILBREAK", "LABEL_1"})


__all__ = ["PROMPT_GUARD_2_22M", "PROMPT_GUARD_2_86M", "PromptGuardDetector"]
