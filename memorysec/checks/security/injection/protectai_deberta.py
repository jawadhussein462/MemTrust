"""Protect AI DeBERTa-v3 prompt-injection classifier.

``protectai/deberta-v3-base-prompt-injection-v2`` (Apache-2.0) labels English
text ``SAFE`` or ``INJECTION``. It is tuned for injected *instructions*
rather than jailbreak role-play, which suits memory screening; it does not
cover non-English text. The same model powers LLM Guard's PromptInjection
scanner.

    pip install "memorysec[hf]"
"""

from __future__ import annotations

from .._hf import HFTextClassifierDetector

PROTECTAI_DEBERTA_V2 = "protectai/deberta-v3-base-prompt-injection-v2"


class ProtectAIDeBERTaDetector(HFTextClassifierDetector):
    """Protect AI ``deberta-v3-base-prompt-injection-v2`` (``INJECTION`` = positive)."""

    name = "protectai_deberta"
    model_id = PROTECTAI_DEBERTA_V2
    positive_labels = frozenset({"INJECTION", "LABEL_1"})


__all__ = ["PROTECTAI_DEBERTA_V2", "ProtectAIDeBERTaDetector"]
