"""Shared fixtures for the MemorySec test suite (builders live in factories.py)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from memorysec import MemorySec
from memorysec.context import CheckContext
from tests.factories import make_context


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def guard() -> MemorySec:
    return MemorySec()


@pytest.fixture
def context() -> CheckContext:
    return make_context()
