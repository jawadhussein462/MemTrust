"""Small CLI: ``memtrust check``.

Built on argparse (stdlib) so the core package needs no CLI dependency.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .client import MemTrust


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
    return parser


def _cmd_check(args: argparse.Namespace) -> int:
    guard = MemTrust()
    decision = guard.check_write(args.content)
    if args.json:
        print(decision.model_dump_json(indent=2))
    else:
        print(str(decision))
    return 0 if decision.allowed else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
