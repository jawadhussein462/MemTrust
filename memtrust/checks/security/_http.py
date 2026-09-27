"""Minimal JSON-over-HTTPS transport for hosted detectors (stdlib only).

Hosted detectors (Azure Prompt Shields, Lakera Guard) take a ``transport``
callable ``(url, headers, payload) -> response_json`` so they can be tested
offline or routed through the caller's HTTP client. :func:`urllib_transport`
is the default.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from ...exceptions import BackendError

Transport = Callable[[str, Mapping[str, str], Mapping[str, Any]], Any]


def urllib_transport(timeout: float = 10.0) -> Transport:
    """A transport that POSTs JSON with :mod:`urllib` and parses the JSON reply."""

    def post(url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Any:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise BackendError(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise BackendError(f"{url}: {exc}") from exc

    return post


__all__ = ["Transport", "urllib_transport"]
