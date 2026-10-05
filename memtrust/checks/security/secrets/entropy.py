"""High-entropy string detection (the ``detect-secrets`` approach, stdlib only).

Random tokens -- API keys, session ids, signing secrets -- have far higher
Shannon entropy than words. Following Yelp's ``detect-secrets``
``HexHighEntropyString`` / ``Base64HighEntropyString`` plugins, any run of
base64-alphabet characters at least ``min_length`` long with entropy above
``base64_limit`` (default 4.5 bits/char), or hex characters above
``hex_limit`` (default 3.0), is reported. This catches unknown key formats
that no regex covers, at the cost of flagging things like content hashes;
raise the limits or ``min_length`` if that is a problem for your data.

Evidence reports the token *kind* and its entropy, never the token.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ....exceptions import ConfigurationError
from ..base import BaseDetector, Detection

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_ALPHA_ONLY = re.compile(r"^[A-Za-z]+$")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character in ``value``."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class EntropyDetector(BaseDetector):
    """Flag high-entropy runs that look like machine-generated secrets."""

    name = "entropy"

    def __init__(
        self,
        *,
        base64_limit: float = 4.5,
        hex_limit: float = 3.0,
        min_length: int = 20,
    ) -> None:
        if not 0.0 <= base64_limit <= 8.0 or not 0.0 <= hex_limit <= 8.0:
            raise ConfigurationError("entropy limits must be within [0, 8].")
        if min_length < 8:
            raise ConfigurationError("min_length must be >= 8.")
        self.base64_limit = base64_limit
        self.hex_limit = hex_limit
        self.min_length = min_length

    def high_entropy_kinds(self, text: str) -> dict[str, float]:
        """``{"hex": entropy, "base64": entropy}`` for the strongest run of each kind."""
        found: dict[str, float] = {}
        for match in _HEX_RUN.finditer(text):
            token = match.group(0)
            if len(token) >= self.min_length:
                entropy = shannon_entropy(token)
                if entropy > self.hex_limit:
                    found["hex"] = max(found.get("hex", 0.0), entropy)
        for match in _BASE64_RUN.finditer(text):
            token = match.group(0).rstrip("=")
            if len(token) < self.min_length or _ALPHA_ONLY.match(token):
                continue
            if _HEX_RUN.fullmatch(token):
                continue  # already judged by the hex rule
            entropy = shannon_entropy(token)
            if entropy > self.base64_limit:
                found["base64"] = max(found.get("base64", 0.0), entropy)
        return found

    def mask(self, text: str) -> str:
        """Replace high-entropy runs with bullets. Leaves ordinary words alone."""

        def _hex(match: re.Match[str]) -> str:
            token = match.group(0)
            if len(token) >= self.min_length and shannon_entropy(token) > self.hex_limit:
                return "••••••••"
            return token

        def _b64(match: re.Match[str]) -> str:
            token = match.group(0)
            body = token.rstrip("=")
            if len(body) < self.min_length or _ALPHA_ONLY.match(body) or _HEX_RUN.fullmatch(body):
                return token
            if shannon_entropy(body) > self.base64_limit:
                return "••••••••"
            return token

        return _BASE64_RUN.sub(_b64, _HEX_RUN.sub(_hex, text))

    def detect_text(self, text: str) -> list[Detection]:
        found = self.high_entropy_kinds(text)
        if not found:
            return []
        best = max(found.values())
        return [
            self.hit(
                code="secret_detected",
                score=min(1.0, best / 6.0),
                kinds=[f"high_entropy_{kind}" for kind in sorted(found)],
                entropy=round(best, 2),
            )
        ]


__all__ = ["EntropyDetector", "shannon_entropy"]
