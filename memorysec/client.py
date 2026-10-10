"""The public facade: :class:`MemorySec` and :class:`AsyncMemorySec`.

``MemorySec`` is the one object most users import. It wires the check
pipeline so ``MemorySec().scan(...)`` just works. Sync and async are
separate classes; a method is never sometimes-async.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ._coerce import coerce_record
from .checks import default_checks
from .checks.base import MemoryCheck
from .config import Config
from .engine import Evaluator
from .exceptions import ConfigurationError
from .models.memory import MemoryRecord
from .models.results import ScanReport
from .telemetry import Tracer


class _ClientBase:
    """Shared construction and pure logic for the sync/async clients."""

    def __init__(
        self,
        *,
        fail_closed: bool | None = None,
        checks: Sequence[Any] | None = None,
        config: Config | None = None,
        tracer: Tracer | None = None,
        use_default_checks: bool = True,
    ) -> None:
        base_config = config or Config()
        updates: dict[str, Any] = {}
        if fail_closed is not None:
            updates["fail_closed"] = fail_closed
        self.config: Config = base_config.model_copy(update=updates) if updates else base_config

        # A user check named like a default ("injection", "secrets", ...) replaces
        # it, so a configured ``InjectionCheck(detectors=[...])`` slots into the
        # default pipeline instead of running alongside the heuristic one.
        resolved_checks: list[MemoryCheck] = list(default_checks()) if use_default_checks else []
        for chk in checks or []:
            if not isinstance(chk, MemoryCheck):
                raise ConfigurationError(f"{type(chk).__name__} is not a MemoryCheck.")
            position = next(
                (i for i, existing in enumerate(resolved_checks) if existing.name == chk.name),
                None,
            )
            if position is None:
                resolved_checks.append(chk)
            else:
                resolved_checks[position] = chk

        self._evaluator = Evaluator(
            config=self.config,
            checks=resolved_checks,
            tracer=tracer,
        )

    def scan(self, source: Iterable[Any], *, query: str | None = None) -> ScanReport:
        """Find poisoned facts, hidden instructions, and leaked secrets.

        ``source`` is a scan source (``.records()``), an object with
        ``.all()``, or an iterable of records or dicts. A concrete sequence
        is one batch, so retrieval-aware detectors see the other records and
        ``query`` when you pass one. Streaming sources are not buffered.
        Nothing is modified.
        """
        records_fn = getattr(source, "records", None)
        if callable(records_fn):
            items: Iterable[Any] = records_fn()
        elif callable(getattr(source, "all", None)):
            items = source.all()
        elif isinstance(source, Iterable) and not isinstance(source, str | bytes | dict):
            items = source
        else:
            raise ConfigurationError(
                f"Cannot scan {type(source).__name__}: pass a scan source, "
                "an object with .all(), or an iterable of records."
            )
        if isinstance(items, Sequence) and not isinstance(items, str | bytes):
            records: Iterable[MemoryRecord] = [coerce_record(item) for item in items]
        else:
            records = (coerce_record(item) for item in items)
        return self._evaluator.scan(records, query=query)


class MemorySec(_ClientBase):
    """Synchronous entry point.

    Example::

        report = MemorySec().scan(records)
        print(report)
    """


class AsyncMemorySec(_ClientBase):
    """Asynchronous entry point. Mirrors :class:`MemorySec`."""

    async def scan(self, source: Iterable[Any], *, query: str | None = None) -> ScanReport:
        return super().scan(source, query=query)


__all__ = [
    "AsyncMemorySec",
    "MemorySec",
]
