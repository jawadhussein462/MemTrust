"""Lakera Guard / Check Point AI Guardrails (hosted).

``POST https://api.lakera.ai/v2/guard`` screens OpenAI-style ``messages``
and returns ``flagged`` plus, with ``breakdown=true``, one entry per
detector (``detector_type``, ``detected``). Lakera Guard tops the PINT
prompt-injection benchmark (95.2%) and screens tool outputs and reference
documents, so a memory is sent as a ``tool`` message by default (indirect
content) -- set ``role="user"`` to screen it as a direct prompt.

The API key comes from ``api_key`` or ``LAKERA_GUARD_API_KEY``. Only the
candidate text is sent. With the project in *detect* mode Lakera forces
``flagged`` to ``false``; this detector therefore also honours per-detector
``detected`` flags in the breakdown when ``use_breakdown`` is on (default),
restricted to prompt-attack detector types.
"""

from __future__ import annotations

import os
from typing import Any

from ....exceptions import ConfigurationError
from .._http import Transport, urllib_transport
from ..base import BaseDetector, Detection

LAKERA_GUARD_URL = "https://api.lakera.ai/v2/guard"
# Detector types that indicate an injection / jailbreak rather than e.g. PII.
_ATTACK_TYPES = ("prompt_attack", "prompt_injection", "jailbreak")


class LakeraGuardDetector(BaseDetector):
    """Lakera Guard ``/v2/guard`` screening for prompt attacks."""

    name = "lakera_guard"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        project_id: str | None = None,
        role: str = "tool",
        url: str = LAKERA_GUARD_URL,
        use_breakdown: bool = True,
        transport: Transport | None = None,
        timeout: float = 10.0,
    ) -> None:
        api_key = api_key or os.environ.get("LAKERA_GUARD_API_KEY")
        if not api_key:
            raise ConfigurationError("LakeraGuardDetector needs api_key (or LAKERA_GUARD_API_KEY).")
        self.url = url
        self.project_id = project_id
        self.role = role
        self.use_breakdown = use_breakdown
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._transport = transport or urllib_transport(timeout)

    def guard(self, text: str) -> dict[str, Any]:
        """Raw API response for ``text``."""
        payload: dict[str, Any] = {"messages": [{"role": self.role, "content": text}]}
        if self.project_id:
            payload["project_id"] = self.project_id
        if self.use_breakdown:
            payload["breakdown"] = True
        response = self._transport(self.url, self._headers, payload)
        if not isinstance(response, dict):
            raise ConfigurationError("Lakera Guard returned a non-object response.")
        return response

    def detect_text(self, text: str) -> list[Detection]:
        response = self.guard(text)
        detected_types: set[str] = set()
        for item in response.get("breakdown") or []:
            dtype = str(item.get("detector_type", ""))
            if item.get("detected") and dtype.startswith(_ATTACK_TYPES):
                detected_types.add(dtype)
        flagged = bool(response.get("flagged")) or bool(detected_types)
        if not flagged:
            return []
        if detected_types:
            return [
                self.hit(score=1.0, provider="lakera_guard", detector_types=sorted(detected_types))
            ]
        return [self.hit(score=1.0, provider="lakera_guard")]


__all__ = ["LAKERA_GUARD_URL", "LakeraGuardDetector"]
