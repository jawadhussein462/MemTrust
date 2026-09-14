"""Shared fixtures for the MemTrust test suite (builders live in factories.py)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from memtrust import MemTrust
from memtrust.context import CheckContext
from tests.factories import make_context


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def guard() -> MemTrust:
    return MemTrust()


@pytest.fixture
def context() -> CheckContext:
    return make_context()
