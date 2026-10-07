"""StarPII (``bigcode/starpii``): PII and secrets in *code*.

The BigCode NER model used to scrub The Stack before StarCoder training. It
tags six classes -- ``NAME``, ``EMAIL``, ``KEY``, ``PASSWORD``, ``IP_ADDRESS``,
``USERNAME`` -- in source code across 31+ languages, which makes it the
right pick when memories contain snippets, configs, or logs rather than
prose. The authors recommend ignoring keys shorter than nine characters and
usernames (noisy); the default label map follows that advice. Gated model.

    pip install "memtrust[hf]"
"""

from __future__ import annotations

from .._hf import HFTokenClassifierDetector

STARPII = "bigcode/starpii"

STARPII_SECRET_LABELS: dict[str, str] = {
    "KEY": "secret_detected",
    "PASSWORD": "secret_detected",
}
STARPII_PII_LABELS: dict[str, str] = {
    "EMAIL": "pii_detected",
    "NAME": "pii_detected",
    "IP_ADDRESS": "pii_detected",
    "USERNAME": "pii_detected",
}
STARPII_ALL_LABELS: dict[str, str] = {**STARPII_SECRET_LABELS, **STARPII_PII_LABELS}


class StarPIIDetector(HFTokenClassifierDetector):
    """StarPII token classification for keys and passwords in code-like content."""

    name = "starpii"
    model_id = STARPII
    default_labels = STARPII_SECRET_LABELS


__all__ = [
    "STARPII",
    "STARPII_ALL_LABELS",
    "STARPII_PII_LABELS",
    "STARPII_SECRET_LABELS",
    "StarPIIDetector",
]
