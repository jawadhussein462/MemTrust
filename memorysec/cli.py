"""Command line: `memorysec scan`.

Scan an existing store for poisoned facts, hidden instructions, and leaked
secrets. The HTML report says what to do with each hit; JSON, SARIF, and
Markdown carry the same findings to tickets, code scanning, and CI pages.
Connections are read-only: the command lists and fetches, and it does not
write to the store.

Exit codes follow other security scanners: `0` when the scan finished,
`1` when `--fail-on` is set and a finding reached that severity, `2` on a
usage, connection, or file error.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

from . import __version__
from .client import MemorySec
from .exceptions import ConfigurationError
from .models.enums import Severity
from .models.memory import MemoryRecord
from .models.results import ScanReport, format_scan_summary
from .scan import render_html, render_markdown, render_sarif
from .scan.chroma import ChromaScanSource
from .scan.jsonl import JsonlScanSource
from .scan.pgvector import PgVectorScanSource
from .scan.pinecone import PineconeScanSource
from .scan.qdrant import QdrantScanSource
from .scan.source import DEFAULT_BATCH_SIZE, ScanSource

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITY_CHOICES = [s.value for s in Severity]

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
            "--json for machine-readable findings, --sarif for GitHub code "
            "scanning, --markdown for a CI job summary, --fail-on to gate a "
            "pipeline, and --sample to cap very large stores."
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
    pgvector.add_argument(
        "--embedding-column",
        default=None,
        help="Column that holds the stored vector (enables hubness and TrustRAG NN).",
    )
    pgvector.add_argument(
        "--created-at-column",
        default=None,
        help="Column that holds the insert time (enables temporal NLI).",
    )
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
        help="Write the full report as JSON (versioned schema, one object per finding).",
    )
    parser.add_argument(
        "--sarif",
        dest="sarif_path",
        metavar="PATH",
        help="Write SARIF 2.1.0 for GitHub code scanning. Snippets are left out.",
    )
    parser.add_argument(
        "--markdown",
        dest="markdown_path",
        metavar="PATH",
        help="Write a Markdown summary, e.g. to $GITHUB_STEP_SUMMARY or a PR comment.",
    )
    parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        metavar="SEVERITY",
        default=None,
        help=(
            "Exit 1 when any finding is at this severity or worse "
            f"({', '.join(_SEVERITY_CHOICES)}). Default: never fail on findings."
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print only the counts, not the table of findings.",
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
            embedding_column=args.embedding_column,
            created_at_column=args.created_at_column,
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
        return EXIT_ERROR
    report.source = label
    report.sample = args.sample

    report_path: str | None = None
    json_path: str | None = None
    outputs: list[tuple[str, str]] = []
    writers: list[tuple[str | None, str, Callable[[ScanReport], str]]] = [
        (args.report, "html", render_html),
        (args.json_path, "json", lambda r: r.model_dump_json(indent=2) + "\n"),
        (args.sarif_path, "SARIF", render_sarif),
        (args.markdown_path, "Markdown summary", render_markdown),
    ]
    try:
        for path, kind, render in writers:
            if not path:
                continue
            Path(path).write_text(render(report), encoding="utf-8")
            if kind == "html":
                report_path = path
            elif kind == "json":
                json_path = path
            else:
                outputs.append((kind, path))
    except OSError as exc:
        print(
            _summary(report, args, report_path=report_path, json_path=json_path, outputs=outputs),
            flush=True,
        )
        print(f"memorysec scan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(
        _summary(report, args, report_path=report_path, json_path=json_path, outputs=outputs),
        flush=True,
    )
    if args.fail_on:
        threshold = Severity(args.fail_on)
        failing = report.at_or_above(threshold)
        if failing:
            noun = "finding" if len(failing) == 1 else "findings"
            print(
                f"memorysec scan: {len(failing):,} {noun} at {threshold.value} or above "
                f"(--fail-on {threshold.value})",
                file=sys.stderr,
            )
            return EXIT_FINDINGS
    return EXIT_OK


def _summary(
    report: ScanReport,
    args: argparse.Namespace,
    *,
    report_path: str | None = None,
    json_path: str | None = None,
    outputs: list[tuple[str, str]] | None = None,
) -> str:
    return format_scan_summary(
        report,
        report_path=report_path,
        json_path=json_path,
        color=_color_enabled(),
        details=not args.quiet,
        outputs=outputs or (),
    )


def _color_enabled() -> bool:
    """Decide whether the scan summary may use terminal color.

    Returns:
        `False` when `NO_COLOR` is set to any non-empty value, or when
        `TERM` is `dumb`. Otherwise `True`.

        A missing TTY does not turn color off. IDE runners often fail
        `isatty` and would otherwise print the summary in plain text.
    """
    if os.environ.get("NO_COLOR", "") != "":
        return False
    return os.environ.get("TERM") != "dumb"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line tool.

    Args:
        argv: Arguments after the program name, such as
            `["scan", "jsonl", "export.jsonl"]`. `None` reads `sys.argv`.

    Returns:
        `0` when the scan finished and any requested files were written.
        `1` when `--fail-on` is set and a finding reached that severity.
        `2` when the arguments, the store, or a file write failed.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    parser.error("unknown command")  # pragma: no cover
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
