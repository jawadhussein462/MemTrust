"""Perplexity filtering: flag text a language model finds implausible.

The classic baseline defence (Jain et al., *Baseline Defenses for Adversarial
Attacks Against Aligned Language Models*, 2023; Alon & Kamfonas, 2023).
Gradient-optimised adversarial passages -- HotFlip / GCG-style suffixes,
white-box PoisonedRAG -- read as gibberish to a causal LM and have far
higher perplexity than natural text. Fluent, LLM-written poison does *not*
(PoisonedRAG and TrustRAG both show clean/poisoned perplexity overlapping),
so treat this as one voter for the adversarial-suffix case, never the only
poisoning detector.

The perplexity function is injectable; the default loads a small causal LM
through ``transformers`` (``gpt2`` unless ``model_id`` says otherwise) and
computes ``exp(mean token NLL)``. ``threshold`` must be calibrated on your
own clean memories: perplexities of ordinary English sentences under GPT-2
are typically in the tens to low hundreds.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

from ....exceptions import ConfigurationError
from .._hf import require_transformers
from ..base import BaseDetector, Detection

Perplexity = Callable[[str], float]
DEFAULT_MODEL = "gpt2"


def _load_perplexity(model_id: str, device: str | None, max_length: int) -> Perplexity:
    transformers = require_transformers()
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ConfigurationError(
            "PerplexityDetector needs 'torch': pip install 'memtrust[hf]'"
        ) from exc
    tokenizer = transformers.AutoTokenizer.from_pretrained(model_id)
    model = transformers.AutoModelForCausalLM.from_pretrained(model_id)
    if device:
        model.to(device)
    model.eval()

    def perplexity(text: str) -> float:
        encoded: Any = tokenizer(text, return_tensors="pt", truncation=True, max_length=max_length)
        if device:
            encoded = {k: v.to(device) for k, v in encoded.items()}
        with torch.no_grad():
            out = model(**encoded, labels=encoded["input_ids"])
        return float(math.exp(float(out.loss)))

    return perplexity


class PerplexityDetector(BaseDetector):
    """Flag text whose causal-LM perplexity exceeds ``threshold``."""

    name = "perplexity"

    def __init__(
        self,
        *,
        threshold: float = 1000.0,
        perplexity: Perplexity | None = None,
        model_id: str = DEFAULT_MODEL,
        device: str | None = None,
        max_length: int = 1024,
        min_words: int = 6,
    ) -> None:
        if threshold <= 1.0:
            raise ConfigurationError("threshold must be greater than 1 (perplexity is >= 1).")
        self.threshold = threshold
        self.model_id = model_id
        self.device = device
        self.max_length = max_length
        self.min_words = max(1, min_words)
        self._perplexity: Perplexity | None = perplexity

    def perplexity(self, text: str) -> float:
        if self._perplexity is None:
            self._perplexity = _load_perplexity(self.model_id, self.device, self.max_length)
        return self._perplexity(text)

    def detect_text(self, text: str) -> list[Detection]:
        if len(text.split()) < self.min_words:
            return []
        ppl = self.perplexity(text)
        if ppl < self.threshold:
            return []
        # Score saturates as perplexity runs past the threshold.
        score = min(1.0, 0.5 + 0.5 * (1 - self.threshold / ppl))
        return [
            self.hit(
                code="adversarial_text",
                score=score,
                perplexity=round(ppl, 1),
                threshold=self.threshold,
                model=self.model_id,
            )
        ]


__all__ = ["DEFAULT_MODEL", "PerplexityDetector"]
