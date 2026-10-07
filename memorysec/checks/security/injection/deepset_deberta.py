"""deepset DeBERTa-v3 injection classifier (``deepset/deberta-v3-base-injection``).

An earlier open classifier trained on the ``deepset/prompt-injections``
dataset, labelling text ``LEGIT`` or ``INJECTION``. Weaker than the Protect
AI v2 model on public benchmarks but cheap and permissively licensed; useful
as a second voter with ``InjectionCheck(min_detectors=2)``.

    pip install "memorysec[hf]"
"""

from __future__ import annotations

from .._hf import HFTextClassifierDetector

DEEPSET_DEBERTA = "deepset/deberta-v3-base-injection"


class DeepsetDeBERTaDetector(HFTextClassifierDetector):
    """deepset ``deberta-v3-base-injection`` (``INJECTION`` = positive)."""

    name = "deepset_deberta"
    model_id = DEEPSET_DEBERTA
    positive_labels = frozenset({"INJECTION", "LABEL_1"})


__all__ = ["DEEPSET_DEBERTA", "DeepsetDeBERTaDetector"]
