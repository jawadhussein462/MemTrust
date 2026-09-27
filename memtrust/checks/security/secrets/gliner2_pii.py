"""GLiNER2-PII (``fastino/gliner2-privacy-filter-PII-multi``).

A 205M-parameter GLiNER2 fine-tune that extracts 42 PII entity types in
seven languages in one forward pass, with the label schema given *at
inference time* -- so the detector asks only for the labels it maps. Its
"secrets / credentials" group (``password``, ``secret``, ``api_key``,
``access_token``, ``recovery_code``) plus payment and government-ID labels
map to ``secret_detected`` by default; contact and name labels are
available as ``pii_detected`` through ``GLINER2_ALL_LABELS``.

    pip install "memtrust[gliner2]"     # the ``gliner2`` package (CPU-friendly)
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ....exceptions import ConfigurationError
from ..base import BaseDetector, Detection

GLINER2_PII = "fastino/gliner2-privacy-filter-PII-multi"

GLINER2_SECRET_LABELS: dict[str, str] = {
    "password": "secret_detected",
    "secret": "secret_detected",
    "api_key": "secret_detected",
    "access_token": "secret_detected",
    "recovery_code": "secret_detected",
    "card_number": "secret_detected",
    "card_cvv": "secret_detected",
    "payment_card": "secret_detected",
    "iban": "secret_detected",
    "bank_account": "secret_detected",
    "account_number": "secret_detected",
    "routing_number": "secret_detected",
    "national_id_number": "secret_detected",
    "passport_number": "secret_detected",
    "drivers_license_number": "secret_detected",
    "tax_id": "secret_detected",
    "sensitive_account_id": "secret_detected",
}
GLINER2_PII_LABELS: dict[str, str] = {
    "person": "pii_detected",
    "full_name": "pii_detected",
    "email": "pii_detected",
    "phone_number": "pii_detected",
    "address": "pii_detected",
    "street_address": "pii_detected",
    "date_of_birth": "pii_detected",
    "username": "pii_detected",
    "ip_address": "pii_detected",
    "government_id": "pii_detected",
}
GLINER2_ALL_LABELS: dict[str, str] = {**GLINER2_SECRET_LABELS, **GLINER2_PII_LABELS}

# ``(text, labels) -> {"entities": {label: [{"text": ..., "confidence": ...}, ...]}}``
Extract = Callable[[str, list[str]], Mapping[str, Any]]


class GLiNER2PIIDetector(BaseDetector):
    """GLiNER2-PII schema-driven entity extraction, scoped to credential labels."""

    name = "gliner2_pii"

    def __init__(
        self,
        *,
        model_id: str = GLINER2_PII,
        labels: Mapping[str, str] | None = None,
        threshold: float = 0.5,
        extract: Extract | None = None,
        chunk_size: int = 384,
        chunk_overlap: int = 64,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ConfigurationError("threshold must be within [0, 1].")
        self.model_id = model_id
        self.labels: dict[str, str] = dict(labels if labels is not None else GLINER2_SECRET_LABELS)
        if not self.labels:
            raise ConfigurationError("GLiNER2PIIDetector needs a non-empty labels mapping.")
        self.threshold = threshold
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self._extract: Extract | None = extract

    def _load(self) -> Extract:
        try:
            from gliner2 import GLiNER2
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ConfigurationError(
                "GLiNER2PIIDetector needs the 'gliner2' package: pip install 'memtrust[gliner2]'"
            ) from exc
        model = GLiNER2.from_pretrained(self.model_id)

        def extract(text: str, labels: list[str]) -> Mapping[str, Any]:
            result = model.extract_entities_long(
                text,
                labels,
                threshold=self.threshold,
                include_confidence=True,
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
            )
            return result if isinstance(result, Mapping) else {}

        return extract

    def extract(self, text: str) -> Mapping[str, Any]:
        if self._extract is None:
            self._extract = self._load()
        return self._extract(text, sorted(self.labels))

    def detect_text(self, text: str) -> list[Detection]:
        entities = self.extract(text).get("entities") or {}
        found: dict[str, tuple[set[str], float]] = {}
        for label, items in entities.items():
            code = self.labels.get(str(label))
            if code is None or not items:
                continue
            best = 0.0
            for item in items:
                confidence = (
                    float(item.get("confidence", 1.0)) if isinstance(item, Mapping) else 1.0
                )
                best = max(best, confidence)
            if best < self.threshold:
                continue
            kinds, prev = found.get(code, (set(), 0.0))
            kinds.add(str(label))
            found[code] = (kinds, max(prev, best))
        return [
            self.hit(code=code, score=best, kinds=sorted(kinds), model=self.model_id)
            for code, (kinds, best) in sorted(found.items())
        ]


__all__ = [
    "GLINER2_ALL_LABELS",
    "GLINER2_PII",
    "GLINER2_PII_LABELS",
    "GLINER2_SECRET_LABELS",
    "GLiNER2PIIDetector",
]
