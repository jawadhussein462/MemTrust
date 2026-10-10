"""Normalize text and compare two strings.

Uses only the Python standard library. Detectors call these helpers before
matching patterns or measuring how alike two memories are. Nothing here is
stored back into the memory.
"""

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
    """Undo common tricks used to hide a phrase from a regex.

    The result is only for matching. It is not written back to the store.

    The steps are: Unicode NFKC normalize, drop invisible characters, map
    Cyrillic and Greek look-alikes to Latin, strip accents, and join
    letters spelled out one by one (`"i-g-n-o-r-e"` becomes `"ignore"`).

    Args:
        text: The memory content, unchanged.

    Returns:
        A new string that is easier for phrase patterns to match.
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
    """Make two strings easier to compare as words.

    Args:
        text: Any string.

    Returns:
        `text` in lowercase, with punctuation replaced by spaces and
        repeated whitespace collapsed to a single space.
    """
    text = text.lower()
    text = _PUNCT.sub(" ", text)
    return _WS.sub(" ", text).strip()


def tokenize(text: str) -> list[str]:
    """Split `text` into words after `normalize`.

    Args:
        text: Any string.

    Returns:
        Lowercase words, in order. Empty when `text` has no words.
    """
    return normalize(text).split()


def token_set(text: str, *, drop_stopwords: bool = True) -> set[str]:
    """Return the unique words in `text`.

    Args:
        text: Any string. It is normalized before the split.
        drop_stopwords: When `True` (the default), drop filler words such
            as "the" and "and" so they do not count as similarity.

    Returns:
        A set of lowercase words. Order is not preserved.
    """
    tokens = set(tokenize(text))
    if drop_stopwords:
        tokens -= _STOPWORDS
    return tokens


def jaccard(a: str, b: str) -> float:
    """Score how much the word sets of `a` and `b` overlap.

    Args:
        a: First text.
        b: Second text.

    Returns:
        A float from 0 to 1. `1` means the same words (after dropping
        filler words). `0` means no shared words. Two empty texts return `1`.
    """
    sa, sb = token_set(a), token_set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def ratio(a: str, b: str) -> float:
    """Score how similar `a` and `b` are as character sequences.

    Args:
        a: First text.
        b: Second text.

    Returns:
        A float from 0 to 1 from `difflib.SequenceMatcher` on the normalized
        strings. `1` means the normalized texts are identical.
    """
    return difflib.SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def similarity(a: str, b: str) -> float:
    """Score how alike two texts are, using whichever measure is higher.

    Args:
        a: First text.
        b: Second text.

    Returns:
        The larger of `jaccard(a, b)` and `ratio(a, b)`, from 0 to 1.
    """
    return max(jaccard(a, b), ratio(a, b))


def _lcs_length(a: list[str], b: list[str]) -> int:
    if not a or not b:
        return 0
    previous = [0] * (len(b) + 1)
    for token in a:
        current = [0]
        for j, other in enumerate(b, start=1):
            current.append(
                previous[j - 1] + 1 if token == other else max(previous[j], current[j - 1])
            )
        previous = current
    return previous[-1]


def rouge_l(a: str, b: str) -> float:
    """Score how much of the word order is shared, via the longest common subsequence.

    Args:
        a: First text.
        b: Second text.

    Returns:
        An F1 score from 0 to 1. `0` means no shared word sequence.
        Higher means the two texts reuse a longer run of the same words,
        even with gaps.
    """
    ta, tb = tokenize(a), tokenize(b)
    lcs = _lcs_length(ta, tb)
    if lcs == 0:
        return 0.0
    precision, recall = lcs / len(tb), lcs / len(ta)
    return 2 * precision * recall / (precision + recall)


def cosine(a: list[float], b: list[float]) -> float:
    """Score how aligned two embedding vectors are.

    Args:
        a: First vector.
        b: Second vector. Must be the same length as `a`.

    Returns:
        Cosine similarity. `1` means the same direction, `0` means
        perpendicular or a zero-length vector. Negative values mean
        opposite directions.

    Raises:
        ValueError: The two lists have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("vectors must have the same dimension")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if not norm_a or not norm_b:
        return 0.0
    return dot / (norm_a * norm_b)


__all__ = [
    "cosine",
    "deobfuscate",
    "jaccard",
    "normalize",
    "ratio",
    "rouge_l",
    "similarity",
    "token_set",
    "tokenize",
]
