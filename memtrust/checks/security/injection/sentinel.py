"""Qualifire Sentinel (``qualifire/prompt-injection-sentinel``).

A ModernBERT-large classifier (labels ``benign`` / ``jailbreak``) trained
on a broad mix of instruction-hijacking, role-play, and biased-content
attacks. Reports 0.938 average F1 across four public injection benchmarks
versus 0.709 for the Protect AI DeBERTa baseline (Sentinel paper,
arXiv:2506.05446). ModernBERT's long context (8k tokens) means fewer chunks
for long documents.

    pip install "memtrust[hf]"
"""

from __future__ import annotations

from .._hf import HFTextClassifierDetector

SENTINEL = "qualifire/prompt-injection-sentinel"


class SentinelDetector(HFTextClassifierDetector):
    """Qualifire ``prompt-injection-sentinel`` (``jailbreak`` = positive)."""

    name = "sentinel"
    model_id = SENTINEL
    positive_labels = frozenset({"JAILBREAK", "INJECTION", "MALICIOUS", "LABEL_1"})

    def __init__(self, **kwargs: object) -> None:
        kwargs.setdefault("max_length", 8192)
        kwargs.setdefault("chunk_chars", 20000)
        super().__init__(**kwargs)  # type: ignore[arg-type]


__all__ = ["SENTINEL", "SentinelDetector"]
