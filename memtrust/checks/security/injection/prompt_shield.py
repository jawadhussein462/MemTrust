"""Azure AI Content Safety **Prompt Shields** (hosted).

``POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01``
analyses a ``userPrompt`` (direct attacks) and up to five ``documents``
(indirect attacks: instructions hidden in third-party content). Memories are
third-party content from the agent's point of view, so the candidate is sent
as a *document* by default and the reply's
``documentsAnalysis[0].attackDetected`` is used. The API returns a boolean,
not a score.

Credentials come from ``endpoint`` / ``key`` or the
``AZURE_CONTENT_SAFETY_ENDPOINT`` / ``AZURE_CONTENT_SAFETY_KEY`` environment
variables. Nothing beyond the candidate text is sent; nothing is logged.
"""

from __future__ import annotations

import os
from typing import Any

from ....exceptions import ConfigurationError
from .._http import Transport, urllib_transport
from ..base import BaseDetector, Detection

API_VERSION = "2024-09-01"
# The API accepts at most 10k characters per document.
MAX_DOCUMENT_CHARS = 10_000


class PromptShieldDetector(BaseDetector):
    """Azure Prompt Shields: document attack (indirect injection) detection."""

    name = "prompt_shield"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        key: str | None = None,
        as_user_prompt: bool = False,
        api_version: str = API_VERSION,
        transport: Transport | None = None,
        timeout: float = 10.0,
    ) -> None:
        endpoint = endpoint or os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT")
        key = key or os.environ.get("AZURE_CONTENT_SAFETY_KEY")
        if not endpoint or not key:
            raise ConfigurationError(
                "PromptShieldDetector needs endpoint and key (or AZURE_CONTENT_SAFETY_ENDPOINT / "
                "AZURE_CONTENT_SAFETY_KEY)."
            )
        self.url = (
            f"{endpoint.rstrip('/')}/contentsafety/text:shieldPrompt?api-version={api_version}"
        )
        self._headers = {"Ocp-Apim-Subscription-Key": key}
        self.as_user_prompt = as_user_prompt
        self._transport = transport or urllib_transport(timeout)

    def shield(self, text: str) -> dict[str, Any]:
        """Raw API response for ``text``."""
        text = text[:MAX_DOCUMENT_CHARS]
        payload: dict[str, Any] = (
            {"userPrompt": text, "documents": []}
            if self.as_user_prompt
            else {"userPrompt": "", "documents": [text]}
        )
        response = self._transport(self.url, self._headers, payload)
        if not isinstance(response, dict):
            raise ConfigurationError("Prompt Shields returned a non-object response.")
        return response

    def detect_text(self, text: str) -> list[Detection]:
        response = self.shield(text)
        if self.as_user_prompt:
            detected = bool((response.get("userPromptAnalysis") or {}).get("attackDetected"))
            mode = "user_prompt"
        else:
            docs = response.get("documentsAnalysis") or []
            detected = bool(docs and docs[0].get("attackDetected"))
            mode = "document"
        if not detected:
            return []
        return [self.hit(score=1.0, provider="azure_prompt_shields", mode=mode)]


__all__ = ["PromptShieldDetector"]
