"""Time helpers. Leaf module with no internal dependencies."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    """Coerce a naive datetime to UTC; leave aware datetimes untouched."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


__all__ = ["ensure_aware", "utcnow"]
