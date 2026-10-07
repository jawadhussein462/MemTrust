"""Piiranha-v1 (``iiiorg/piiranha-v1-detect-personal-information``).

An mDeBERTa-v3 token classifier trained to tag 17 PII types in six
languages (98% of PII tokens caught on its test set; especially strong on
passwords, emails, phone numbers, usernames). Labels are BIO-style
``I-PASSWORD``, ``I-CREDITCARDNUMBER``, ... and the context window is 256
tokens, so content is scanned in chunks. Licence: CC-BY-NC-ND-4.0 -- check
it fits your deployment.

By default only credential-like labels map to ``secret_detected`` (block).
Pass ``labels=PIIRANHA_ALL_LABELS`` (or your own mapping) to also report
personal data as ``pii_detected`` (review).

    pip install "memtrust[hf]"
"""

from __future__ import annotations

from .._hf import HFTokenClassifierDetector

PIIRANHA_V1 = "iiiorg/piiranha-v1-detect-personal-information"

PIIRANHA_SECRET_LABELS: dict[str, str] = {
    "PASSWORD": "secret_detected",
    "CREDITCARDNUMBER": "secret_detected",
    "SOCIALNUM": "secret_detected",
    "ACCOUNTNUM": "secret_detected",
    "IDCARDNUM": "secret_detected",
    "DRIVERLICENSENUM": "secret_detected",
    "TAXNUM": "secret_detected",
}
PIIRANHA_PII_LABELS: dict[str, str] = {
    "EMAIL": "pii_detected",
    "TELEPHONENUM": "pii_detected",
    "USERNAME": "pii_detected",
    "GIVENNAME": "pii_detected",
    "SURNAME": "pii_detected",
    "DATEOFBIRTH": "pii_detected",
    "STREET": "pii_detected",
    "BUILDINGNUM": "pii_detected",
    "CITY": "pii_detected",
    "ZIPCODE": "pii_detected",
}
PIIRANHA_ALL_LABELS: dict[str, str] = {**PIIRANHA_SECRET_LABELS, **PIIRANHA_PII_LABELS}


class PiiranhaDetector(HFTokenClassifierDetector):
    """Piiranha-v1 token classification; credential labels block, PII labels review."""

    name = "piiranha"
    model_id = PIIRANHA_V1
    default_labels = PIIRANHA_SECRET_LABELS

    def __init__(self, **kwargs: object) -> None:
        kwargs.setdefault("chunk_chars", 600)  # ~256 mDeBERTa tokens
        super().__init__(**kwargs)  # type: ignore[arg-type]


__all__ = [
    "PIIRANHA_ALL_LABELS",
    "PIIRANHA_PII_LABELS",
    "PIIRANHA_SECRET_LABELS",
    "PIIRANHA_V1",
    "PiiranhaDetector",
]
