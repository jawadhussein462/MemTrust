"""Injectable clock, so time-dependent checks are deterministic in tests."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ._time import ensure_aware, utcnow


@runtime_checkable
class Clock(Protocol):
    """Something that can report the current time."""

    def now(self) -> datetime: ...


class SystemClock:
    """Wall-clock time in UTC."""

    def now(self) -> datetime:
        return utcnow()


class FixedClock:
    """A clock frozen at a fixed instant. Useful for tests."""

    def __init__(self, instant: datetime) -> None:
        self._instant = ensure_aware(instant)

    def now(self) -> datetime:
        return self._instant

    def set(self, instant: datetime) -> None:
        self._instant = ensure_aware(instant)


__all__ = ["Clock", "FixedClock", "SystemClock"]
