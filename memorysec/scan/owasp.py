"""OWASP Agentic Top 10, item ASI06: Memory and Context Poisoning.

Every MemorySec finding is a stored-memory issue under ASI06: poisoned facts,
hidden instructions, and leaked secrets that stay in memory across turns.
The constants here are the id, title, and URL written on reports.
"""

from __future__ import annotations

ASI06_ID = "ASI06"
ASI06_TITLE = "Memory & Context Poisoning"
ASI06_REF = "ASI06: Memory & Context Poisoning"
ASI06_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/"

__all__ = ["ASI06_ID", "ASI06_REF", "ASI06_TITLE", "ASI06_URL"]
