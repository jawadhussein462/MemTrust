"""Audit stores, serialization, redaction, and filtering."""

from __future__ import annotations

from memtrust import MemTrust
from memtrust.audit import InMemoryAuditStore, JSONLAuditStore
from memtrust.audit.base import AuditEvent
from memtrust.models.enums import AuditEventType


def test_inmemory_records_write_events():
    store = InMemoryAuditStore()
    guard = MemTrust(audit_store=store)
    guard.check_write("hi")
    types = {e.type for e in store.list()}
    assert AuditEventType.WRITE_REQUESTED in types
    assert any(t in types for t in (AuditEventType.WRITE_ALLOWED, AuditEventType.WRITE_BLOCKED))


def test_audit_event_is_json_serializable():
    event = AuditEvent(type=AuditEventType.WRITE_ALLOWED, finding_codes=["x"])
    restored = AuditEvent.model_validate_json(event.model_dump_json())
    assert restored.type is AuditEventType.WRITE_ALLOWED


def test_secrets_never_appear_in_audit():
    store = InMemoryAuditStore()
    guard = MemTrust(audit_store=store)
    guard.check_write("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    blob = "".join(e.model_dump_json() for e in store.list())
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in blob
    assert "REDACTED" in blob


def test_jsonl_round_trip_and_filter(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = JSONLAuditStore(path)
    store.append(AuditEvent(type=AuditEventType.WRITE_ALLOWED, memory_id="m1"))
    store.append(AuditEvent(type=AuditEventType.WRITE_BLOCKED, memory_id="m2"))
    store.append(AuditEvent(type=AuditEventType.WRITE_ALLOWED, memory_id="m1"))

    assert len(store.list()) == 3
    assert len(store.list(memory_id="m1")) == 2
    assert len(store.list(type=AuditEventType.WRITE_BLOCKED)) == 1
    assert len(store.list(limit=1)) == 1


def test_inmemory_filters_by_memory_id():
    store = InMemoryAuditStore()
    store.append(AuditEvent(type=AuditEventType.READ_ALLOWED, memory_id="m1"))
    store.append(AuditEvent(type=AuditEventType.READ_ALLOWED, memory_id="m2"))
    got = store.list(type=AuditEventType.READ_ALLOWED, memory_id="m1")
    assert len(got) == 1 and got[0].memory_id == "m1"
