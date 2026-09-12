"""Lightweight text normalization and similarity. Leaf module (stdlib only)."""

from __future__ import annotations

import difflib
import re

_PUNCT = re.compile(r"[^\w\s]")
_WS = re.compile(r"\s+")

# Common filler words ignored when comparing token sets.
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "to",
        "of",
        "in",
        "on",
        "at",
        "for",
        "and",
        "or",
        "but",
        "with",
        "that",
        "this",
        "it",
        "as",
        "by",
        "from",
        "now",
        "then",
    }
)


def normalize(text: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    text = text.lower()
    text = _PUNCT.sub(" ", text)
    return _WS.sub(" ", text).strip()


def tokenize(text: str) -> list[str]:
    return normalize(text).split()


def token_set(text: str, *, drop_stopwords: bool = True) -> set[str]:
    tokens = set(tokenize(text))
    if drop_stopwords:
        tokens -= _STOPWORDS
    return tokens


def jaccard(a: str, b: str) -> float:
    """Jaccard similarity of the two token sets (0..1)."""
    sa, sb = token_set(a), token_set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def ratio(a: str, b: str) -> float:
    """Character-sequence similarity on normalized text (0..1)."""
    return difflib.SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def similarity(a: str, b: str) -> float:
    """Combined similarity: max of Jaccard and sequence ratio."""
    return max(jaccard(a, b), ratio(a, b))


__all__ = ["jaccard", "normalize", "ratio", "similarity", "token_set", "tokenize"]
