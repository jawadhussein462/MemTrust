"""Model behaviour: coercion, enums, serialization."""

from __future__ import annotations

import pytest

from memtrust import (
    Action,
    MemoryCandidate,
    MemoryRecord,
    Severity,
)
from memtrust._coerce import coerce_candidate
from memtrust.exceptions import ConfigurationError


def test_severity_and_action_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Action.BLOCK.precedence > Action.DELETE.precedence > Action.QUARANTINE.precedence
    assert Action.ALLOW.is_allowed
    assert not Action.BLOCK.is_allowed
    assert not Action.DELETE.is_allowed


def test_candidate_to_record_carries_lineage():
    c = MemoryCandidate(content="fact", derived_from=["mem_a"])
    r = c.to_record(id="mem_b")
    assert r.id == "mem_b"
    assert "mem_a" in r.derived_from


def test_record_json_round_trip():
    r = MemoryRecord(id="m", content="c")
    dumped = r.model_dump_json()
    restored = MemoryRecord.model_validate_json(dumped)
    assert restored.id == r.id
    assert restored.content == "c"


def test_coerce_candidate_from_string_and_dict():
    from_str = coerce_candidate("hello")
    assert from_str.content == "hello"
    from_dict = coerce_candidate({"content": "hi"})
    assert from_dict.content == "hi"
    already = MemoryCandidate(content="x")
    assert coerce_candidate(already) is already


@pytest.mark.parametrize("bad", [123, 4.5, object()])
def test_coerce_candidate_rejects_bad_types(bad):
    with pytest.raises(ConfigurationError):
        coerce_candidate(bad)
