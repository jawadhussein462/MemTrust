"""Small CLI: ``memtrust check`` and ``memtrust audit``.

Built on argparse (stdlib) so the core package needs no CLI dependency.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .client import MemTrust
from .models.enums import AuditEventType


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

    audit = sub.add_parser("audit", help="Show local JSONL audit data.")
    audit.add_argument("file", help="Path to a .jsonl audit file.")
    audit.add_argument(
        "--type",
        choices=[t.value for t in AuditEventType],
        default=None,
        help="Filter by event type.",
    )
    audit.add_argument("--limit", type=int, default=20, help="Max events to show.")
    audit.add_argument("--json", action="store_true", help="Emit JSON lines.")
    return parser


def _cmd_check(args: argparse.Namespace) -> int:
    guard = MemTrust()
    decision = guard.check_write(args.content)
    if args.json:
        print(decision.model_dump_json(indent=2))
    else:
        print(str(decision))
    return 0 if decision.allowed else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    from .audit.jsonl import JSONLAuditStore

    store = JSONLAuditStore(args.file)
    event_type = AuditEventType(args.type) if args.type else None
    events = store.list(type=event_type, limit=args.limit)
    if not events:
        print("No audit events found.")
        return 0
    for event in events:
        if args.json:
            print(event.model_dump_json())
        else:
            ts = event.timestamp.isoformat(timespec="seconds")
            codes = ",".join(event.finding_codes) or "-"
            action = event.action.value if event.action else "-"
            print(f"{ts}  {event.type.value:<18} action={action:<12} findings={codes}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "audit":
        return _cmd_audit(args)
    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
