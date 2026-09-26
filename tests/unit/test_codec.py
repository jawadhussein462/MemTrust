"""Record-state codec used by the RAG adapters."""

from __future__ import annotations

import json

from memtrust import MemoryStatus
from memtrust.integrations._codec import STATE_KEY, decode_record, state_metadata
from tests.factories import make_record


def test_state_round_trips_with_store_id_and_content():
    record = make_record("Alice prefers tea.", status="superseded", derived_from=["doc_1"])
    decoded = decode_record(state_metadata(record), id=record.id, content=record.content)
    assert decoded == record


def test_store_id_and_content_are_authoritative():
    record = make_record("original", id="mem_a")
    decoded = decode_record(state_metadata(record), id="mem_b", content="as stored")
    assert (decoded.id, decoded.content) == ("mem_b", "as stored")


def test_missing_state_means_unmanaged_active_record():
    decoded = decode_record({"source": "crawler"}, id="doc_1", content="text")
    assert decoded.status == MemoryStatus.ACTIVE
    assert decode_record(None, id="doc_1", content="text").status == MemoryStatus.ACTIVE


def test_unreadable_state_fails_closed():
    for raw in ["{not json", json.dumps({"status": "no-such-status"}), json.dumps([1, 2])]:
        decoded = decode_record({STATE_KEY: raw}, id="mem_x", content="text")
        assert decoded.status == MemoryStatus.QUARANTINED


def test_unknown_fields_from_newer_versions_are_ignored():
    raw = json.dumps({"status": "revoked", "future_field": {"x": 1}})
    decoded = decode_record({STATE_KEY: raw}, id="mem_x", content="text")
    assert decoded.status == MemoryStatus.REVOKED
