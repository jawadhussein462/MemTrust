"""Shared bases for Hugging Face ``transformers`` detectors.

``transformers`` (and ``torch``) are imported lazily, on first use, so the
core package stays dependency-free. Every detector accepts an injectable
inference callable (``classify=`` / ``tag=``) so it can be unit-tested, or
backed by a remote inference endpoint, without loading weights.

Install with ``pip install "memorysec[hf]"``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ...exceptions import ConfigurationError
from .base import BaseDetector, Detection

# One label prediction: ``{"label": "MALICIOUS", "score": 0.99}``.
LabelScores = list[dict[str, Any]]
Classify = Callable[[str], LabelScores]
# One tagged entity: ``{"entity_group": "PASSWORD", "score": 0.98, "start": 3, "end": 9}``.
Entities = list[dict[str, Any]]
Tag = Callable[[str], Entities]

_WS = re.compile(r"\s+")
_BIO = re.compile(r"^[BIES]-")


def require_transformers() -> Any:
    try:
        import transformers
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ConfigurationError(
            "This detector needs the 'transformers' package: pip install 'memorysec[hf]'"
        ) from exc
    return transformers


def chunk_text(text: str, chunk_chars: int | None) -> list[str]:
    """Split on whitespace into chunks of at most ``chunk_chars`` characters.

    Classifiers see a fixed context window (typically 512 tokens); scanning
    every chunk and taking the worst score catches payloads buried late in a
    long document instead of silently truncating them.
    """
    if not chunk_chars or len(text) <= chunk_chars:
        return [text]
    chunks: list[str] = []
    current: list[str] = []
    size = 0  # len(" ".join(current))
    for word in _WS.split(text.strip()):
        extra = len(word) + (1 if current else 0)
        if current and size + extra > chunk_chars:
            chunks.append(" ".join(current))
            current, size, extra = [], 0, len(word)
        current.append(word)
        size += extra
    if current:
        chunks.append(" ".join(current))
    return chunks or [text]


class HFTextClassifierDetector(BaseDetector):
    """A sequence classifier whose positive labels signal the concern.

    Subclasses set ``model_id`` and ``positive_labels``. The detection score
    is the highest positive-label probability over all chunks; a detection is
    emitted when it reaches ``threshold``.
    """

    model_id: str = ""
    positive_labels: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        model_id: str | None = None,
        threshold: float = 0.5,
        positive_labels: Iterable[str] | None = None,
        classify: Classify | None = None,
        device: int | str | None = None,
        max_length: int = 512,
        chunk_chars: int | None = 1500,
        name: str | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ConfigurationError("threshold must be within [0, 1].")
        self.model_id = model_id or type(self).model_id
        if not self.model_id:
            raise ConfigurationError(f"{type(self).__name__} needs a model_id.")
        self.threshold = threshold
        source = positive_labels if positive_labels is not None else type(self).positive_labels
        self.positive_labels = frozenset(label.upper() for label in source)
        if not self.positive_labels:
            raise ConfigurationError(f"{type(self).__name__} needs positive_labels.")
        self.device = device
        self.max_length = max_length
        self.chunk_chars = chunk_chars
        if name:
            self.name = name
        self._classify: Classify | None = classify

    # -- inference -----------------------------------------------------------------

    def _load(self) -> Classify:
        transformers = require_transformers()
        kwargs: dict[str, Any] = {"model": self.model_id, "top_k": None}
        if self.device is not None:
            kwargs["device"] = self.device
        pipe = transformers.pipeline("text-classification", **kwargs)

        def classify(text: str) -> LabelScores:
            out = pipe(text, truncation=True, max_length=self.max_length)
            # ``top_k=None`` yields ``[[{label, score}, ...]]`` for a single input.
            if out and isinstance(out[0], list):
                return list(out[0])
            return list(out)

        return classify

    def classify(self, text: str) -> LabelScores:
        if self._classify is None:
            self._classify = self._load()
        return self._classify(text)

    def positive_score(self, text: str) -> tuple[float, str | None]:
        """Highest positive-label score across chunks and the label that produced it."""
        best, label = 0.0, None
        for chunk in chunk_text(text, self.chunk_chars):
            for item in self.classify(chunk):
                item_label = str(item.get("label", "")).upper()
                if item_label in self.positive_labels and float(item["score"]) > best:
                    best, label = float(item["score"]), item_label
        return best, label

    def detect_text(self, text: str) -> list[Detection]:
        score, label = self.positive_score(text)
        if label is None or score < self.threshold:
            return []
        return [self.hit(score=score, label=label.lower(), model=self.model_id)]


class HFTokenClassifierDetector(BaseDetector):
    """A token classifier (NER-style) mapping entity labels to finding codes.

    ``labels`` maps an entity label (``"PASSWORD"``) to the code the parent
    check should emit (``"secret_detected"``). Entities with other labels are
    ignored, so a PII model can be scoped to credentials only. Evidence lists
    the entity *kinds* found -- never the matched text.
    """

    model_id: str = ""
    default_labels: Mapping[str, str] = {}

    def __init__(
        self,
        *,
        model_id: str | None = None,
        labels: Mapping[str, str] | None = None,
        threshold: float = 0.5,
        tag: Tag | None = None,
        device: int | str | None = None,
        chunk_chars: int | None = 1000,
        name: str | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ConfigurationError("threshold must be within [0, 1].")
        self.model_id = model_id or type(self).model_id
        if not self.model_id:
            raise ConfigurationError(f"{type(self).__name__} needs a model_id.")
        source = labels if labels is not None else type(self).default_labels
        self.labels: dict[str, str] = {k.upper(): v for k, v in source.items()}
        if not self.labels:
            raise ConfigurationError(f"{type(self).__name__} needs a non-empty labels mapping.")
        self.threshold = threshold
        self.device = device
        self.chunk_chars = chunk_chars
        if name:
            self.name = name
        self._tag: Tag | None = tag

    def _load(self) -> Tag:
        transformers = require_transformers()
        kwargs: dict[str, Any] = {"model": self.model_id, "aggregation_strategy": "simple"}
        if self.device is not None:
            kwargs["device"] = self.device
        pipe = transformers.pipeline("token-classification", **kwargs)
        return lambda text: list(pipe(text))

    def tag(self, text: str) -> Entities:
        if self._tag is None:
            self._tag = self._load()
        return self._tag(text)

    def entity_kinds(self, text: str) -> dict[str, tuple[set[str], float]]:
        """Per code: the entity kinds seen and the best score, above threshold."""
        found: dict[str, tuple[set[str], float]] = {}
        for chunk in chunk_text(text, self.chunk_chars):
            for entity in self.tag(chunk):
                raw = str(entity.get("entity_group") or entity.get("entity") or "")
                label = _BIO.sub("", raw).upper()
                score = float(entity.get("score", 1.0))
                code = self.labels.get(label)
                if code is None or score < self.threshold:
                    continue
                kinds, best = found.get(code, (set(), 0.0))
                kinds.add(label.lower())
                found[code] = (kinds, max(best, score))
        return found

    def detect_text(self, text: str) -> list[Detection]:
        return [
            self.hit(code=code, score=best, kinds=sorted(kinds), model=self.model_id)
            for code, (kinds, best) in sorted(self.entity_kinds(text).items())
        ]


__all__ = [
    "Classify",
    "Entities",
    "HFTextClassifierDetector",
    "HFTokenClassifierDetector",
    "LabelScores",
    "Tag",
    "chunk_text",
    "require_transformers",
]
