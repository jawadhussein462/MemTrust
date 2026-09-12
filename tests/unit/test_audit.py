"""Audit stores, serialization, redaction, and filtering."""

from __future__ import annotations

from memtrust import MemTrust
from memtrust.audit import InMemoryAuditStore, JSONLAuditStore
from memtrust.audit.base import AuditEvent
from memtrust.models.enums import AuditEventType


def test_inmemory_records_write_events():
    store = InMemoryAuditStore()
    guard = MemTrust(audit_store=store)
    guard.check_write("hi", source={"type": "a", "trust": "user"}, scope={"tenant_id": "acme"})
    types = {e.type for e in store.list()}
    assert AuditEventType.WRITE_REQUESTED in types
    assert any(t in types for t in (AuditEventType.WRITE_ALLOWED, AuditEventType.WRITE_BLOCKED))


def test_audit_event_is_json_serializable():
    event = AuditEvent(type=AuditEventType.WRITE_ALLOWED, tenant_id="acme", finding_codes=["x"])
    restored = AuditEvent.model_validate_json(event.model_dump_json())
    assert restored.type is AuditEventType.WRITE_ALLOWED
    assert restored.tenant_id == "acme"


def test_secrets_never_appear_in_audit():
    store = InMemoryAuditStore()
    guard = MemTrust(audit_store=store)
    guard.check_write(
        "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        source={"type": "a", "trust": "user"},
        scope={"tenant_id": "acme"},
    )
    blob = "".join(e.model_dump_json() for e in store.list())
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in blob
    assert "REDACTED" in blob


def test_jsonl_round_trip_and_filter(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = JSONLAuditStore(path)
    store.append(AuditEvent(type=AuditEventType.WRITE_ALLOWED, tenant_id="acme"))
    store.append(AuditEvent(type=AuditEventType.WRITE_BLOCKED, tenant_id="globex"))
    store.append(AuditEvent(type=AuditEventType.WRITE_ALLOWED, tenant_id="acme"))

    assert len(store.list()) == 3
    assert len(store.list(tenant_id="acme")) == 2
    assert len(store.list(type=AuditEventType.WRITE_BLOCKED)) == 1
    assert len(store.list(limit=1)) == 1


def test_inmemory_filters_by_memory_id():
    store = InMemoryAuditStore()
    store.append(AuditEvent(type=AuditEventType.READ_ALLOWED, memory_id="m1", agent_id="a1"))
    store.append(AuditEvent(type=AuditEventType.READ_ALLOWED, memory_id="m2", agent_id="a2"))
    got = store.list(type=AuditEventType.READ_ALLOWED, memory_id="m1")
    assert len(got) == 1 and got[0].agent_id == "a1"
