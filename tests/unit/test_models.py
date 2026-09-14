"""Model behaviour: coercion, enums, serialization, Decision."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from memtrust import (
    Action,
    Decision,
    Finding,
    MemoryCandidate,
    MemoryRecord,
    Risk,
    Severity,
)
from memtrust._coerce import coerce_candidate
from memtrust.exceptions import ConfigurationError


def test_severity_and_action_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Action.BLOCK.precedence > Action.QUARANTINE.precedence > Action.SUPERSEDE.precedence
    assert Action.ALLOW.is_allowed
    assert not Action.BLOCK.is_allowed


def test_candidate_to_record_carries_lineage():
    c = MemoryCandidate(content="fact", derived_from=["mem_a"])
    r = c.to_record(id="mem_b")
    assert r.id == "mem_b"
    assert "mem_a" in r.derived_from


def test_record_expiry_and_liveness():
    now = datetime.now(UTC)
    r = MemoryRecord(id="m", content="c", expires_at=now - timedelta(hours=1))
    assert r.is_expired(now)
    assert not r.is_live(now)
    r2 = MemoryRecord(id="m2", content="c")
    assert r2.is_live(now)


def test_decision_convenience_properties():
    findings = [
        Finding(code="a", severity="low", message="lo"),
        Finding(code="b", severity="critical", message="hi"),
    ]
    d = Decision(
        allowed=False,
        action=Action.QUARANTINE,
        recommended_action=Action.QUARANTINE,
        risk=Risk.CRITICAL,
        findings=findings,
    )
    assert d.blocked
    assert len(d.errors) == 1 and d.errors[0].code == "b"
    assert len(d.warnings) == 1 and d.warnings[0].code == "a"
    assert d.reason == "hi"
    assert set(d.finding_codes()) == {"a", "b"}


def test_decision_str_is_readable():
    d = Decision(
        allowed=False,
        action=Action.QUARANTINE,
        recommended_action=Action.QUARANTINE,
        risk=Risk.CRITICAL,
        findings=[Finding(code="memory_poisoning", severity="critical", message="m")],
    )
    text = str(d)
    assert "BLOCKED" in text
    assert "critical" in text
    assert "memory_poisoning" in text
    assert "quarantine" in text


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
