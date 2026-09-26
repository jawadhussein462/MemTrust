"""Small CLI: ``memtrust check`` and ``memtrust scan``.

Built on argparse (stdlib) so the core package needs no CLI dependency.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from typing import IO, Any

from . import __version__
from .client import MemTrust
from .exceptions import ConfigurationError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memtrust",
        description="Security and correctness for agent long-term knowledge memory.",
    )
    parser.add_argument("--version", action="version", version=f"memtrust {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate whether a memory should be written.")
    check.add_argument("content", help="The candidate memory text.")
    check.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    scan = sub.add_parser(
        "scan",
        help="Audit exported memories (JSON Lines) for what reads would withhold.",
        description=(
            "Audit a memory export. Each line is a JSON object with at least "
            "'content' (and optionally 'id', 'status', 'expires_at', ...). "
            "Reports ids and finding codes only, never content. Exits 1 if any "
            "active record would be withheld."
        ),
    )
    scan.add_argument("path", help="JSON Lines file, or '-' for stdin.")
    scan.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return parser


def _cmd_check(args: argparse.Namespace) -> int:
    guard = MemTrust()
    decision = guard.check_write(args.content)
    if args.json:
        print(decision.model_dump_json(indent=2))
    else:
        print(str(decision))
    return 0 if decision.allowed else 1


def _jsonl_records(stream: IO[str]) -> Iterator[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"line {lineno}: invalid JSON ({exc.msg})") from exc
        if not isinstance(item, dict) or not isinstance(item.get("content"), str):
            raise ConfigurationError(f"line {lineno}: expected an object with a 'content' string")
        item.setdefault("id", f"line_{lineno}")
        yield item


def _cmd_scan(args: argparse.Namespace) -> int:
    guard = MemTrust()
    try:
        if args.path == "-":
            report = guard.scan(_jsonl_records(sys.stdin))
        else:
            with open(args.path, encoding="utf-8") as fh:
                report = guard.scan(_jsonl_records(fh))
    except (OSError, ConfigurationError, ValueError) as exc:
        print(f"memtrust scan: {exc}", file=sys.stderr)
        return 2
    print(report.model_dump_json(indent=2) if args.json else str(report))
    return 1 if report.flagged else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "scan":
        return _cmd_scan(args)
    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
