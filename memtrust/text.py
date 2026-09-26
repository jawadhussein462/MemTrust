"""Lightweight text normalization and similarity. Leaf module (stdlib only)."""

from __future__ import annotations

import difflib
import re
import unicodedata

_PUNCT = re.compile(r"[^\w\s]")
_WS = re.compile(r"\s+")

# Invisible characters used to split trigger words ("ig\u200bnore").
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"))
# Common Cyrillic/Greek look-alikes of Latin letters.
_CONFUSABLES = str.maketrans(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u0410\u0415\u041e"
    "\u0420\u0421\u0425\u0406\u0408\u0405\u03bf\u03b9\u03b1\u03b5\u039f\u0399\u0391\u0395",
    "aeopcyxijsdAEOPCXIJSoiaeOIAE",
)
# Single letters joined by separators: "i-g-n-o-r-e", "i.g.n.o.r.e", "i g n o r e".
_SPACED = re.compile(r"\b[A-Za-z](?:[-._*]|\s)(?:[A-Za-z](?:[-._*]|\s)){2,}[A-Za-z]\b")
_SEPARATORS = re.compile(r"[-._*\s]")


def deobfuscate(text: str) -> str:
    """Undo common obfuscation before pattern matching (never stored).

    NFKC-normalizes, drops invisible characters, maps Cyrillic/Greek
    look-alikes to Latin, strips diacritics, and joins letter-by-letter
    spelling ("i-g-n-o-r-e" -> "ignore").
    """
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).translate(_CONFUSABLES)
    text = "".join(
        ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)
    )
    return _SPACED.sub(lambda m: _SEPARATORS.sub("", m.group(0)), text)


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


# Words that introduce a value: "limit is 100", "costs 40", "meeting at 3pm".
_VALUE_CUES = frozenset(
    {"is", "are", "was", "were", "equals", "costs", "cost", "at", "to", "of", "now", "by", "about"}
)


def _has_digit(token: str) -> bool:
    return any(ch.isdigit() for ch in token)


def value_change(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` state the same attribute with a different number.

    "The API rate limit is 100 rps" vs "... is 500 rps" is a value change,
    not a duplicate. The number must follow a value cue so that identifiers
    ("order 123 shipped" vs "order 456 shipped") are not treated as values.
    """
    ta, tb = tokenize(a), tokenize(b)
    nums_a = [t for t in ta if _has_digit(t)]
    nums_b = [t for t in tb if _has_digit(t)]
    if not nums_a or not nums_b or nums_a == nums_b:
        return False
    words_a = {t for t in ta if not _has_digit(t)} - _STOPWORDS
    words_b = {t for t in tb if not _has_digit(t)} - _STOPWORDS
    union = words_a | words_b
    if not union or len(words_a & words_b) / len(union) < 0.8:
        return False
    first_a = next(i for i, t in enumerate(ta) if _has_digit(t))
    first_b = next(i for i, t in enumerate(tb) if _has_digit(t))
    return bool(set(ta[max(0, first_a - 3) : first_a]) & _VALUE_CUES) and bool(
        set(tb[max(0, first_b - 3) : first_b]) & _VALUE_CUES
    )


__all__ = [
    "deobfuscate",
    "jaccard",
    "normalize",
    "ratio",
    "similarity",
    "token_set",
    "tokenize",
    "value_change",
]
