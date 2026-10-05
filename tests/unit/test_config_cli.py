"""Config helpers and the CLI."""

from __future__ import annotations

from memtrust.config import Config


def test_config_defaults():
    cfg = Config()
    assert cfg.fail_closed is True
    assert cfg.read_checks is True
