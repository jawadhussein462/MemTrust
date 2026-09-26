"""Integration/adapter tests against fakes (no provider SDKs needed)."""

from __future__ import annotations

import pytest

from memtrust import MemoryStatus, MemTrust
from memtrust.backends import InMemoryBackend
from memtrust.exceptions import BackendError
from memtrust.integrations.chroma import ChromaBackend
from memtrust.integrations.langchain import LangChainVectorStoreBackend
from memtrust.integrations.langgraph import LangGraphStoreBackend
from memtrust.integrations.llamaindex import LlamaIndexBackend
from memtrust.integrations.mem0 import Mem0Backend
from memtrust.integrations.qdrant import QdrantBackend
from tests.fakes import (
    FakeChroma,
    FakeLlamaIndex,
    FakeMem0,
    FakeMem0V3,
    FakeQdrant,
    FakeStore,
    FakeVectorStore,
    function_backend,
)

BACKENDS = {
    "inmemory": InMemoryBackend,
    "function": function_backend,
    "mem0": lambda: Mem0Backend(FakeMem0()),
    "langgraph": lambda: LangGraphStoreBackend(FakeStore()),
    "chroma": lambda: ChromaBackend(FakeChroma()),
    "qdrant": lambda: QdrantBackend(FakeQdrant()),
    "llamaindex": lambda: LlamaIndexBackend(FakeLlamaIndex()),
    "langchain": lambda: LangChainVectorStoreBackend(FakeVectorStore()),
}


@pytest.mark.parametrize("name", list(BACKENDS))
def test_backend_conformance_round_trip(name):
    mem = MemTrust().protect(BACKENDS[name]())
    result = mem.add("Alice prefers annual billing.")
    assert result.allowed
    found = mem.search("billing")
    assert any("annual billing" in s.memory for s in found)


def test_mem0_reconstructs_record_from_metadata():
    mem = MemTrust().protect(Mem0Backend(FakeMem0()))
    mem.add("Alice likes tea.")
    results = mem.search("tea")
    assert results and "tea" in results[0].memory


def test_mem0_platform_v3_round_trip_uses_filters_and_uuid():
    fake = FakeMem0V3()
    backend = Mem0Backend(fake, search_filters=True)
    mem = MemTrust().protect(backend)
    result = mem.add("Alice prefers annual billing.")
    assert result.allowed and result.record is not None
    assert not result.record.id.startswith("mem_")
    stored = fake._d[result.record.id]
    assert stored["infer"] is False
    found = mem.search("billing")
    assert any("annual billing" in s.memory for s in found)
    got = mem.get(result.record.id)
    assert got is not None and got.id == result.record.id


def test_mem0_platform_search_does_not_pass_top_level_user_id():
    fake = FakeMem0V3()
    mem = MemTrust().protect(Mem0Backend(fake, search_filters=True))
    mem.add("Alice likes tea.")
    found = mem.search("tea")
    assert any("tea" in s.memory for s in found)


def test_mem0_get_invalid_id_is_a_miss():
    mem = MemTrust().protect(Mem0Backend(FakeMem0V3(), search_filters=True))
    assert mem.get("mem_not_a_uuid") is None


def test_mem0_add_error_is_backend_error():
    class Boom:
        def add(self, *a, **k):
            raise RuntimeError("nope")

        def search(self, *a, **k):
            return {"results": []}

    mem = MemTrust().protect(Mem0Backend(Boom()))
    with pytest.raises(BackendError, match="Mem0 add failed"):
        mem.add("x")


def test_langgraph_get_and_delete_by_id():
    backend = LangGraphStoreBackend(FakeStore())
    mem = MemTrust().protect(backend)
    r = mem.add("Find me.")
    assert backend.get(r.record.id) is not None
    backend.delete(r.record.id)
    assert backend.get(r.record.id) is None


@pytest.mark.parametrize(
    "backend_factory",
    [
        lambda: ChromaBackend(FakeChroma()),
        lambda: QdrantBackend(FakeQdrant()),
        lambda: LlamaIndexBackend(FakeLlamaIndex()),
        lambda: LangChainVectorStoreBackend(FakeVectorStore()),
    ],
)
def test_rag_adapters_get_and_delete(backend_factory):
    backend = backend_factory()
    mem = MemTrust().protect(backend)
    r = mem.add("Find me.")
    assert backend.get(r.record.id) is not None
    backend.delete(r.record.id)
    assert backend.get(r.record.id) is None


class FakeMem0OSS2:
    """Mem0 2.x ``Memory`` signatures: identity top-level on add, in filters on search."""

    def __init__(self):
        self.calls = []

    def add(self, messages, *, user_id=None, agent_id=None, run_id=None, metadata=None, infer=True):
        self.calls.append(("add", {"user_id": user_id, "metadata": metadata, "infer": infer}))
        return {"results": [{"id": "u1"}]}

    def search(self, query, *, top_k=20, filters=None, **kwargs):
        if {"user_id", "agent_id", "run_id"} & set(kwargs):
            raise ValueError("Top-level entity parameters are not supported")
        self.calls.append(("search", {"top_k": top_k, "filters": filters, **kwargs}))
        return {"results": []}


def test_mem0_oss2_identity_top_level_on_add_and_in_filters_on_search():
    client = FakeMem0OSS2()
    mem = MemTrust().protect(Mem0Backend(client, user_id="alice"))
    mem.add("Alice prefers tea.")
    mem.search("tea", limit=5)
    adds = [kw for op, kw in client.calls if op == "add"]
    searches = [kw for op, kw in client.calls if op == "search"]
    assert adds[0]["user_id"] == "alice" and adds[0]["infer"] is False
    assert searches[-1] == {"top_k": 5, "filters": {"user_id": "alice"}}


def test_mem0_search_filters_carry_identity():
    fake = FakeMem0V3()
    mem = MemTrust().protect(Mem0Backend(fake, user_id="alice", search_filters=True))
    mem.search("tea", limit=3)
    assert fake.last_search == {"top_k": 3, "filters": {"user_id": "alice"}}


def test_mem0_status_change_updates_in_place():
    fake = FakeMem0()
    mem = MemTrust().protect(Mem0Backend(fake))
    old = mem.add("Alice works at Stripe.")
    mem.add("Alice now works at Anthropic.")
    assert len(fake._d) == 2
    assert Mem0Backend(fake).get(old.id).status == "superseded"


def test_mem0_without_metadata_update_fails_loudly():
    class LegacyMem0(FakeMem0):
        def update(self, mid, data):  # mem0 0.1.x: text only
            raise AssertionError("must not be called")

    mem = MemTrust().protect(Mem0Backend(LegacyMem0()))
    mem.add("Alice works at Stripe.")
    with pytest.raises(BackendError, match="cannot update metadata in place"):
        mem.add("Alice now works at Anthropic.")


def _signature_bound_client(cls, responses):
    """An instance of the real ``cls`` whose methods only bind and record calls."""
    import inspect

    obj = cls.__new__(cls)
    obj.calls = []
    for name, response in responses.items():
        signature = inspect.signature(getattr(obj, name))

        def call(*args, _sig=signature, _name=name, _resp=response, **kwargs):
            _sig.bind(*args, **kwargs)  # TypeError if the real method rejects it
            obj.calls.append((_name, kwargs))
            return _resp

        call.__signature__ = signature
        setattr(obj, name, call)
    return obj


@pytest.mark.parametrize("cls_name", ["Memory", "MemoryClient"])
def test_mem0_calls_bind_to_installed_mem0_signatures(cls_name):
    mem0 = pytest.importorskip("mem0")
    stored = {"id": "u1", "memory": "Alice works at Stripe.", "metadata": {}}
    client = _signature_bound_client(
        getattr(mem0, cls_name),
        {
            "add": {"results": [{"id": "u1"}]},
            "search": {"results": []},
            "get": stored,
            "update": {"message": "ok"},
        },
    )
    backend = Mem0Backend(client, user_id="alice")
    mem = MemTrust().protect(backend)
    mem.add("Alice works at Stripe.")
    mem.search("Alice", limit=5)
    backend.set_status("u1", MemoryStatus.SUPERSEDED)

    calls = dict(client.calls)
    if cls_name == "MemoryClient":
        assert calls["add"]["filters"] == {"user_id": "alice"}
    else:
        assert calls["add"]["user_id"] == "alice"
    assert "user_id" not in calls["search"], "Mem0 2.x rejects top-level identity on search"
    assert calls["search"]["filters"] == {"user_id": "alice"}
    assert "metadata" in calls["update"]
