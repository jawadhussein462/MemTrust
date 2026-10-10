"""Read-only scanners and the reports they produce.

Each `*ScanSource` lists records from one store and never writes. A
`ScanReport` renders as:

* `render_html` — one self-contained file to forward to whoever acts on it.
* `render_markdown` — a summary for CI job pages and pull-request comments.
* `render_sarif` — SARIF 2.1.0 for GitHub code scanning and other viewers.
* `ScanReport.model_dump_json()` — the full machine-readable report.
"""

from __future__ import annotations

from .chroma import ChromaScanSource
from .html import render_html
from .jsonl import JsonlScanSource
from .markdown import render_markdown
from .owasp import (
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
from .pgvector import PgVectorScanSource
from .pinecone import PineconeScanSource
from .qdrant import QdrantScanSource
from .sarif import render_sarif

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
    "ChromaScanSource",
    "JsonlScanSource",
    "PgVectorScanSource",
    "PineconeScanSource",
    "QdrantScanSource",
    "render_html",
    "render_markdown",
    "render_sarif",
]
