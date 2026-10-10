"""Masked snippets for scan reports.

Reports are meant to be forwarded. They show enough of the memory to act
on, and they do not show the secret values that triggered the finding.
"""

from __future__ import annotations

from ..checks.security.secrets.entropy import EntropyDetector
from ..checks.security.secrets.heuristic import mask_secrets

_DEFAULT_WIDTH = 160


def mask_snippet(text: str, *, width: int = _DEFAULT_WIDTH) -> str:
    """Hide secrets in `text` and shorten it for a report line.

    Args:
        text: The full memory content.
        width: Maximum characters in the result. Default 160.

    Returns:
        One line: secrets replaced with bullets, whitespace collapsed, cut
        to `width` characters with a trailing ellipsis when it was longer.
    """
    masked = " ".join(EntropyDetector().mask(mask_secrets(text)).split())
    if len(masked) <= width:
        return masked
    return masked[: width - 1] + "…"


__all__ = ["mask_snippet"]
