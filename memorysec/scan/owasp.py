"""OWASP references used by the HTML report and scan findings.

Canonical constants live in `memorysec.owasp`. This module re-exports them
so existing `memorysec.scan.owasp` imports keep working.
"""

from __future__ import annotations

from ..owasp import (
    ASI06_ID,
    ASI06_REF,
    ASI06_TITLE,
    ASI06_URL,
    LLM01_ID,
    LLM01_REF,
    LLM01_TITLE,
    LLM01_URL,
    LLM02_ID,
    LLM02_REF,
    LLM02_TITLE,
    LLM02_URL,
)

__all__ = [
    "ASI06_ID",
    "ASI06_REF",
    "ASI06_TITLE",
    "ASI06_URL",
    "LLM01_ID",
    "LLM01_REF",
    "LLM01_TITLE",
    "LLM01_URL",
    "LLM02_ID",
    "LLM02_REF",
    "LLM02_TITLE",
    "LLM02_URL",
]
