"""Integration/adapter conformance against fakes (no provider SDKs needed)."""

from __future__ import annotations

import pytest

from memtrust import MemTrust
from memtrust.backends import InMemoryBackend
from memtrust.exceptions import BackendError
from memtrust.integrations.chroma import ChromaBackend
from memtrust.integrations.generic import FunctionBackend
from memtrust.integrations.langchain import LangChainVectorStoreBackend
from memtrust.integrations.langgraph import LangGraphStoreBackend
from memtrust.integrations.llamaindex import LlamaIndexBackend
from memtrust.integrations.mem0 import Mem0Backend
from memtrust.integrations.qdrant import QdrantBackend


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
        }
        return {"results": [{"id": mid}]}

    def search(self, query, **kw):
        return {"results": list(self._d.values())}

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
        return {"results": list(self._d.values())}

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
        search=lambda q, limit: inner.search(q, limit=limit),
        get=inner.get,
        delete=inner.delete,
    )


class FakeChroma:
    def __init__(self):
        self._d = {}

    def add(self, ids, documents, metadatas=None):
        for i, mid in enumerate(ids):
            self._d[mid] = {
                "id": mid,
                "document": documents[i],
                "metadata": (metadatas or [{}])[i] if metadatas else {},
            }

    def query(self, query_texts, n_results=10, where=None):
        items = list(self._d.values())[:n_results]
        return {
            "ids": [[v["id"] for v in items]],
            "documents": [[v["document"] for v in items]],
            "metadatas": [[v["metadata"] for v in items]],
        }

    def get(self, ids=None):
        ids = ids or []
        items = [self._d[i] for i in ids if i in self._d]
        return {
            "ids": [v["id"] for v in items],
            "documents": [v["document"] for v in items],
            "metadatas": [v["metadata"] for v in items],
        }

    def delete(self, ids=None):
        for mid in ids or []:
            self._d.pop(mid, None)


class FakeQdrant:
    def __init__(self):
        self._d = {}

    def upsert(self, collection_name, points):
        for point in points:
            pid = str(point["id"] if isinstance(point, dict) else point.id)
            payload = point["payload"] if isinstance(point, dict) else point.payload
            self._d[pid] = {"id": pid, "payload": payload}

    def scroll(self, collection_name, scroll_filter=None, limit=100, **kw):
        return list(self._d.values())[:limit], None

    def retrieve(self, collection_name, ids):
        return [self._d[str(i)] for i in ids if str(i) in self._d]

    def delete(self, collection_name, points_selector=None, **kw):
        ids = (points_selector or {}).get("points") or []
        for mid in ids:
            self._d.pop(str(mid), None)


class FakeLlamaIndex:
    def __init__(self):
        self.docs = {}

    def insert(self, document):
        doc_id = getattr(document, "doc_id", None) or getattr(document, "id_", None)
        self.docs[str(doc_id)] = document

    def as_retriever(self, similarity_top_k=10):
        return self

    def retrieve(self, query):
        needle = (query or "").lower()
        hits = []
        for doc in self.docs.values():
            text = getattr(doc, "text", "") or ""
            if not needle or needle in text.lower():
                hits.append(type("Hit", (), {"node": doc})())
        return hits[:10]

    @property
    def docstore(self):
        return self

    def get_document(self, doc_id):
        return self.docs.get(str(doc_id))

    def delete_ref_doc(self, doc_id, delete_from_docstore=True):
        self.docs.pop(str(doc_id), None)


class FakeVectorStore:
    def __init__(self):
        self._d = {}

    def add_texts(self, texts, metadatas=None, ids=None):
        ids = ids or [f"lc_{i}" for i in range(len(texts))]
        metadatas = metadatas or [{} for _ in texts]
        for i, mid in enumerate(ids):
            self._d[mid] = type(
                "Doc",
                (),
                {"page_content": texts[i], "metadata": metadatas[i], "id": mid},
            )()
        return ids

    def similarity_search(self, query, k=4, filter=None):
        needle = (query or "").lower()
        hits = []
        for doc in self._d.values():
            if not needle or needle in doc.page_content.lower():
                hits.append(doc)
        return hits[:k]

    def get_by_ids(self, ids):
        return [self._d[i] for i in ids if i in self._d]

    def delete(self, ids):
        for mid in ids or []:
            self._d.pop(mid, None)


BACKENDS = {
    "inmemory": InMemoryBackend,
    "function": _function_backend,
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
