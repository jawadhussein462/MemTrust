"""Model behaviour: coercion, enums, authority, serialization, Decision."""

from __future__ import annotations

from datetime import timedelta

import pytest

from memtrust import (
    Action,
    Decision,
    Finding,
    MemoryCandidate,
    MemoryRecord,
    Risk,
    Scope,
    Severity,
    Source,
    TrustLevel,
)
from memtrust._time import utcnow
from memtrust.models.source import default_authority_for


def test_trust_ordering():
    assert TrustLevel.UNTRUSTED.rank < TrustLevel.USER.rank < TrustLevel.AUTHORITATIVE.rank
    assert TrustLevel.INTERNAL.is_at_least(TrustLevel.USER)
    assert not TrustLevel.USER.is_at_least(TrustLevel.INTERNAL)


def test_severity_and_action_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Action.BLOCK.precedence > Action.QUARANTINE.precedence > Action.SUPERSEDE.precedence
    assert Action.ALLOW.is_allowed
    assert not Action.BLOCK.is_allowed


def test_source_dict_coercion_and_default_authority():
    src = Source.model_validate({"type": "ticket", "trust": "untrusted", "id": "t1"})
    assert src.trust is TrustLevel.UNTRUSTED
    assert src.default_authority == default_authority_for(TrustLevel.UNTRUSTED)


def test_scope_defaults_and_readable_by():
    s = Scope(tenant_id="acme", user_id="alice")
    assert s.readable_by(Scope(tenant_id="acme", user_id="alice"))
    assert not s.readable_by(Scope(tenant_id="acme", user_id="bob"))
    assert not s.readable_by(Scope(tenant_id="globex", user_id="alice"))


def test_candidate_effective_authority_capped_by_source():
    # Default: authority implied by source trust.
    c = MemoryCandidate(content="x", source=Source(type="a", trust="untrusted"))
    assert c.effective_authority == default_authority_for(TrustLevel.UNTRUSTED)
    # Explicit value below the source default is honored (you may lower).
    lowered = MemoryCandidate(content="x", source=Source(type="a", trust="trusted"), authority=0.1)
    assert lowered.effective_authority == 0.1
    # Explicit value above the source default is capped (you may not raise).
    spoof = MemoryCandidate(content="x", source=Source(type="a", trust="untrusted"), authority=0.99)
    assert spoof.effective_authority == default_authority_for(TrustLevel.UNTRUSTED)


def test_candidate_to_record_carries_provenance():
    c = MemoryCandidate(
        content="fact",
        source=Source(type="doc", trust="internal", id="doc1"),
        scope=Scope(tenant_id="acme"),
        derived_from=["mem_a"],
    )
    r = c.to_record(id="mem_b")
    assert r.id == "mem_b"
    assert r.trust is TrustLevel.INTERNAL
    assert "doc1" in r.provenance.source_ids
    assert "mem_a" in r.provenance.derived_from


def test_record_expiry_and_liveness():
    now = utcnow()
    r = MemoryRecord(id="m", content="c", scope=Scope(tenant_id="acme"), expires_at=now - timedelta(hours=1))
    assert r.is_expired(now)
    assert not r.is_live(now)
    r2 = MemoryRecord(id="m2", content="c", scope=Scope(tenant_id="acme"))
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
        findings=[Finding(code="untrusted_policy_write", severity="critical", message="m")],
    )
    text = str(d)
    assert "BLOCKED" in text
    assert "critical" in text
    assert "untrusted_policy_write" in text
    assert "quarantine" in text


def test_record_json_round_trip():
    r = MemoryRecord(id="m", content="c", scope=Scope(tenant_id="acme"), authority=0.5, trust="user")
    dumped = r.model_dump_json()
    restored = MemoryRecord.model_validate_json(dumped)
    assert restored.id == r.id
    assert restored.scope.tenant_id == "acme"
    assert restored.trust is TrustLevel.USER


@pytest.mark.parametrize("bad", [123, 4.5, object()])
def test_source_coercion_rejects_bad_types(bad):
    with pytest.raises(Exception):
        Source.model_validate(bad)
