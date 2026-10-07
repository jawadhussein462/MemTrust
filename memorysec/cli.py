"""CLI: ``memorysec scan``.

Scan finds poisoned facts, hidden instructions, and leaked secrets in an
existing store. The HTML report explains the recommended fix. Connections
are read-only.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from . import __version__
from .client import MemorySec
from .exceptions import ConfigurationError
from .models.memory import MemoryRecord
from .scan import render_html
from .scan.chroma import ChromaScanSource
from .scan.jsonl import JsonlScanSource
from .scan.pgvector import PgVectorScanSource
from .scan.pinecone import PineconeScanSource
from .scan.qdrant import QdrantScanSource
from .scan.source import DEFAULT_BATCH_SIZE, ScanSource

_DESCRIPTION = (
    "Scan your AI agent's memory for poisoned facts, hidden instructions "
    "and leaked secrets, locally, in minutes."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memorysec", description=_DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"memorysec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Find poisoned facts, hidden instructions, and leaked secrets.",
        description=(
            "Find problems in an existing memory store. Connections are "
            "read-only. Use --report for an HTML file you can forward, "
            "--json for machine-readable findings, and --sample to cap "
            "very large stores."
        ),
    )
    sources = scan.add_subparsers(dest="source", required=True)

    chroma = sources.add_parser("chroma", help="Scan a Chroma persistent collection.")
    chroma.add_argument("--path", required=True, help="Path to the Chroma database directory.")
    chroma.add_argument("--collection", required=True, help="Collection name.")
    _add_scan_output_flags(chroma)

    qdrant = sources.add_parser("qdrant", help="Scan a Qdrant collection.")
    qdrant.add_argument("--url", required=True, help="Qdrant HTTP URL.")
    qdrant.add_argument("--collection", required=True, help="Collection name.")
    qdrant.add_argument("--api-key", default=os.environ.get("QDRANT_API_KEY"))
    qdrant.add_argument("--text-field", default=None, help="Payload field that holds the text.")
    _add_scan_output_flags(qdrant)

    pgvector = sources.add_parser("pgvector", help="Scan a Postgres / pgvector table.")
    pgvector.add_argument("--dsn", required=True, help="Postgres connection string.")
    pgvector.add_argument("--table", required=True, help="Table name (schema.table allowed).")
    pgvector.add_argument("--text-column", required=True, help="Column that holds memory text.")
    pgvector.add_argument("--id-column", default="id", help="Column that holds the record id.")
    _add_scan_output_flags(pgvector)

    pinecone = sources.add_parser("pinecone", help="Scan a Pinecone index.")
    pinecone.add_argument("--index", required=True, help="Index name.")
    pinecone.add_argument("--api-key", default=os.environ.get("PINECONE_API_KEY"))
    pinecone.add_argument("--host", default=None, help="Index host (serverless).")
    pinecone.add_argument("--namespace", default="")
    pinecone.add_argument(
        "--text-field",
        default=None,
        help="Metadata field that holds the text (default: content/text/document).",
    )
    _add_scan_output_flags(pinecone)

    jsonl = sources.add_parser("jsonl", help="Scan a JSON Lines export.")
    jsonl.add_argument("path", help="JSON Lines file, or '-' for stdin.")
    _add_scan_output_flags(jsonl)
    return parser


def _add_scan_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="Write a single HTML report (forward this to your boss).",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        metavar="PATH",
        help="Write findings as JSON.",
    )
    parser.add_argument(
        "--sample",
        type=int,
        metavar="N",
        default=None,
        help="Scan at most N records (for very large stores).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Records fetched per round-trip (default: {DEFAULT_BATCH_SIZE}).",
    )


def _records_for(args: argparse.Namespace) -> tuple[Iterator[MemoryRecord], str]:
    sample = args.sample
    batch = args.batch_size
    source = args.source
    src: ScanSource
    if source == "chroma":
        src = ChromaScanSource(path=args.path, collection=args.collection)
        return src.records(batch_size=batch, sample=sample), f"chroma:{args.collection}"
    if source == "qdrant":
        src = QdrantScanSource(
            url=args.url,
            collection=args.collection,
            api_key=args.api_key,
            text_field=args.text_field,
        )
        return src.records(batch_size=min(batch, 256), sample=sample), f"qdrant:{args.collection}"
    if source == "pgvector":
        src = PgVectorScanSource(
            dsn=args.dsn,
            table=args.table,
            text_column=args.text_column,
            id_column=args.id_column,
        )
        return src.records(batch_size=batch, sample=sample), f"pgvector:{args.table}"
    if source == "pinecone":
        src = PineconeScanSource(
            index=args.index,
            api_key=args.api_key,
            host=args.host,
            namespace=args.namespace,
            text_field=args.text_field,
        )
        return src.records(batch_size=min(batch, 100), sample=sample), f"pinecone:{args.index}"
    if source == "jsonl":
        if args.path == "-":
            src = JsonlScanSource(sys.stdin)
            label = "jsonl:stdin"
        else:
            src = JsonlScanSource(args.path)
            label = f"jsonl:{args.path}"
        return src.records(sample=sample), label
    raise ConfigurationError(f"unknown scan source {source!r}")


def _cmd_scan(args: argparse.Namespace) -> int:
    guard = MemorySec()
    try:
        records, label = _records_for(args)
        report = guard.scan(records)
    except (OSError, ConfigurationError, ValueError) as exc:
        print(f"memorysec scan: {exc}", file=sys.stderr)
        return 2
    report.source = label
    report.sample = args.sample
    print(str(report))
    try:
        if args.report:
            Path(args.report).write_text(render_html(report), encoding="utf-8")
            print(f"Wrote HTML report to {args.report}")
        if args.json_path:
            Path(args.json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
            print(f"Wrote JSON findings to {args.json_path}")
    except OSError as exc:
        print(f"memorysec scan: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
