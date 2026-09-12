"""Integration/adapter conformance against fakes (no provider SDKs needed)."""

from __future__ import annotations

import pytest

from memtrust import MemTrust
from memtrust.backends import InMemoryBackend
from memtrust.exceptions import BackendError
from memtrust.integrations.generic import FunctionBackend
from memtrust.integrations.langgraph import LangGraphStoreBackend
from memtrust.integrations.mem0 import Mem0Backend

_SRC = {"type": "conversation", "trust": "user"}


# --- fakes ------------------------------------------------------------------

class FakeMem0:
    def __init__(self):
        self._d = {}
        self._n = 0

    def add(self, messages, **kw):
        self._n += 1
        mid = f"m0_{self._n}"
        self._d[mid] = {
            "id": mid,
            "memory": messages,
            "metadata": kw.get("metadata", {}),
            "user_id": kw.get("user_id"),
        }
        return {"results": [{"id": mid}]}

    def search(self, query, **kw):
        uid = kw.get("user_id")
        return {"results": [v for v in self._d.values() if uid is None or v["user_id"] == uid]}

    def get(self, mid):
        return self._d.get(mid)

    def delete(self, mid):
        self._d.pop(mid, None)


class FakeMem0V3:
    """Platform MemoryClient v2+: search rejects top-level user_id; add returns v3 shapes."""

    def __init__(self):
        self._d = {}
        self._n = 0

    def add(self, messages, **kw):
        self._n += 1
        mid = f"aaaaaaaa-bbbb-cccc-dddd-{self._n:012d}"
        self._d[mid] = {
            "id": mid,
            "memory": messages,
            "metadata": kw.get("metadata", {}),
            "user_id": kw.get("user_id"),
            "infer": kw.get("infer"),
        }
        return {
            "event_id": f"evt_{self._n}",
            "status": "SUCCEEDED",
            "results": [{"id": mid, "event": "ADD", "data": {"memory": messages}}],
        }

    def search(self, query, **kw):
        if "user_id" in kw or "agent_id" in kw:
            raise ValueError(
                "Top-level entity parameters are not supported in search(). "
                "Use filters={'user_id': '...'} instead."
            )
        uid = (kw.get("filters") or {}).get("user_id")
        return {"results": [v for v in self._d.values() if uid is None or v["user_id"] == uid]}

    def get(self, mid):
        if mid.startswith("mem_"):
            raise ValueError("memory_id should be a valid UUID")
        return self._d.get(mid)

    def delete(self, mid):
        self._d.pop(mid, None)


class _Item:
    def __init__(self, namespace, key, value):
        self.namespace = namespace
        self.key = key
        self.value = value


class FakeStore:
    def __init__(self):
        self._d = {}

    def put(self, namespace, key, value):
        self._d[(tuple(namespace), key)] = value

    def get(self, namespace, key):
        v = self._d.get((tuple(namespace), key))
        return _Item(namespace, key, v) if v is not None else None

    def search(self, namespace_prefix, *, query=None, filter=None, limit=10, offset=0):
        pre = tuple(namespace_prefix)
        out = [_Item(ns, key, val) for (ns, key), val in self._d.items() if ns[: len(pre)] == pre]
        return out[:limit]

    def delete(self, namespace, key):
        self._d.pop((tuple(namespace), key), None)


def _function_backend():
    inner = InMemoryBackend()
    return FunctionBackend(
        add=inner.add,
        search=lambda q, scope, limit: inner.search(q, scope=scope, limit=limit),
        get=inner.get,
        delete=inner.delete,
    )


BACKENDS = {
    "inmemory": InMemoryBackend,
    "function": _function_backend,
    "mem0": lambda: Mem0Backend(FakeMem0()),
    "langgraph": lambda: LangGraphStoreBackend(FakeStore()),
}


@pytest.mark.parametrize("name", list(BACKENDS))
def test_backend_conformance_round_trip(name):
    mem = MemTrust().protect(BACKENDS[name]())
    scope = {"tenant_id": "acme", "user_id": "alice", "namespace": "preferences"}
    result = mem.add("Alice prefers annual billing.", source=_SRC, scope=scope)
    assert result.allowed
    found = mem.search("billing", scope=scope)
    assert any("annual billing" in s.memory for s in found)


@pytest.mark.parametrize("name", list(BACKENDS))
def test_backend_conformance_tenant_isolation(name):
    mem = MemTrust().protect(BACKENDS[name]())
    mem.add("ACME secret.", source=_SRC, scope={"tenant_id": "acme", "user_id": "alice"})
    # Even if the backend returned it, the guard must filter cross-tenant.
    leaked = mem.search("secret", scope={"tenant_id": "globex", "user_id": "alice"})
    assert leaked == []


def test_mem0_reconstructs_scope_from_metadata():
    mem = MemTrust().protect(Mem0Backend(FakeMem0()))
    scope = {"tenant_id": "acme", "user_id": "alice"}
    mem.add("Alice likes tea.", source=_SRC, scope=scope)
    results = mem.search("tea", scope=scope)
    assert results and results[0].scope.tenant_id == "acme"


def test_mem0_withholds_unverified_records():
    # A record written outside MemTrust (no provenance metadata) must not be
    # trusted with the requester's tenant; core read enforcement withholds it.
    fake = FakeMem0()
    fake._d["legacy1"] = {"id": "legacy1", "memory": "legacy secret",
                          "metadata": {}, "user_id": "alice"}
    mem = MemTrust().protect(Mem0Backend(fake))
    results = mem.search("secret", scope={"tenant_id": "acme", "user_id": "alice"})
    assert results == []


def test_mem0_trust_native_scope_opt_in():
    fake = FakeMem0()
    fake._d["legacy1"] = {"id": "legacy1", "memory": "legacy note",
                          "metadata": {}, "user_id": "alice"}
    mem = MemTrust().protect(Mem0Backend(fake, trust_native_scope=True))
    results = mem.search("note", scope={"tenant_id": "acme", "user_id": "alice"})
    assert any("legacy note" in s.memory for s in results)


def test_mem0_platform_v3_round_trip_uses_filters_and_uuid():
    fake = FakeMem0V3()
    backend = Mem0Backend(fake, search_filters=True)
    mem = MemTrust().protect(backend)
    scope = {"tenant_id": "acme", "user_id": "alice"}
    result = mem.add("Alice prefers annual billing.", source=_SRC, scope=scope)
    assert result.allowed and result.record is not None
    assert not result.record.id.startswith("mem_")
    stored = fake._d[result.record.id]
    assert stored["infer"] is False
    found = mem.search("billing", scope=scope)
    assert any("annual billing" in s.memory for s in found)
    assert found[0].scope.tenant_id == "acme"
    got = mem.get(result.record.id, scope=scope)
    assert got is not None and got.id == result.record.id


def test_mem0_platform_search_does_not_pass_top_level_user_id():
    fake = FakeMem0V3()
    mem = MemTrust().protect(Mem0Backend(fake, search_filters=True))
    mem.add("Alice likes tea.", source=_SRC, scope={"tenant_id": "acme", "user_id": "alice"})
    # Would raise BackendError if the adapter still passed user_id=...
    found = mem.search("tea", scope={"tenant_id": "acme", "user_id": "alice"})
    assert any("tea" in s.memory for s in found)


def test_mem0_get_invalid_id_is_a_miss():
    mem = MemTrust().protect(Mem0Backend(FakeMem0V3(), search_filters=True))
    assert mem.get("mem_not_a_uuid", scope={"tenant_id": "acme"}) is None


def test_mem0_add_error_is_backend_error():
    class Boom:
        def add(self, *a, **k):
            raise RuntimeError("nope")

        def search(self, *a, **k):
            return {"results": []}

    mem = MemTrust().protect(Mem0Backend(Boom()))
    with pytest.raises(BackendError, match="Mem0 add failed"):
        mem.add("x", source=_SRC, scope={"tenant_id": "acme", "user_id": "alice"})


def test_langgraph_get_and_delete_by_id():
    backend = LangGraphStoreBackend(FakeStore())
    mem = MemTrust().protect(backend)
    r = mem.add("Find me.", source=_SRC, scope={"tenant_id": "acme", "user_id": "u"})
    assert backend.get(r.record.id) is not None
    backend.delete(r.record.id)
    assert backend.get(r.record.id) is None
