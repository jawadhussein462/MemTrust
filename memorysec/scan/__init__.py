"""Read-only scanners and the HTML report they produce.

Each `*ScanSource` lists records from one store and never writes. `render_html`
turns a `ScanReport` into a single file you can forward.
"""

from __future__ import annotations

from .chroma import ChromaScanSource
from .html import render_html
from .jsonl import JsonlScanSource
from .owasp import ASI06_ID, ASI06_REF, ASI06_TITLE, ASI06_URL
from .pgvector import PgVectorScanSource
from .pinecone import PineconeScanSource
from .qdrant import QdrantScanSource

__all__ = [
    "ASI06_ID",
    "ASI06_REF",
    "ASI06_TITLE",
    "ASI06_URL",
    "ChromaScanSource",
    "JsonlScanSource",
    "PgVectorScanSource",
    "PineconeScanSource",
    "QdrantScanSource",
    "render_html",
]
