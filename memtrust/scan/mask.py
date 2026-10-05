"""Masked snippets for scan reports.

Reports are meant to be forwarded. They show enough context to act, and
never the secret values that triggered the finding.
"""

from __future__ import annotations

from ..checks.security.secrets.entropy import EntropyDetector
from ..checks.security.secrets.heuristic import mask_secrets

_DEFAULT_WIDTH = 160


def mask_snippet(text: str, *, width: int = _DEFAULT_WIDTH) -> str:
    """Secret-mask ``text`` and truncate to ``width`` characters."""
    masked = " ".join(EntropyDetector().mask(mask_secrets(text)).split())
    if len(masked) <= width:
        return masked
    return masked[: width - 1] + "…"


__all__ = ["mask_snippet"]
