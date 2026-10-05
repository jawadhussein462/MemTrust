"""In-process fakes of provider SDKs (no provider packages needed).

Each fake mirrors the call shapes of the real client closely enough that the
adapters exercise the same code paths; ``tests/integration/test_backend_conformance.py``
runs the same assertions against the real SDKs when they are installed.
"""

from __future__ import annotations

from memtrust.backends import InMemoryBackend
from memtrust.integrations.generic import FunctionBackend
from memtrust.text import token_set


def _matches(query, text):
    """Keyword match: any shared token (an empty query matches everything)."""
    wanted = token_set(query or "")
    return not wanted or bool(wanted & token_set(text))


class FakeMem0:
    """OSS ``Memory`` shape: server-assigned ids, ``{"results": [...]}`` responses."""

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

    def update(self, mid, metadata=None):
        if metadata is not None and mid in self._d:
            self._d[mid]["metadata"] = metadata
        return {"message": "Memory updated successfully!"}

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
            "filters": kw.get("filters"),
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
        self.last_search = kw
        return {"results": list(self._d.values())}

    def get(self, mid):
        if mid.startswith("mem_"):
            raise ValueError("memory_id should be a valid UUID")
        return self._d.get(mid)

    def update(self, mid, options=None, **kw):
        if "metadata" in kw and mid in self._d:
            self._d[mid]["metadata"] = kw["metadata"]
        return {"message": "Memory updated successfully!"}

    def delete(self, mid):
        self._d.pop(mid, None)


class _Item:
    def __init__(self, namespace, key, value):
        self.namespace = namespace
        self.key = key
        self.value = value


class FakeStore:
    """LangGraph ``BaseStore`` shape."""

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
        return out[offset : offset + limit]

    def delete(self, namespace, key):
        self._d.pop((tuple(namespace), key), None)


def function_backend():
    inner = InMemoryBackend()
    return FunctionBackend(
        add=inner.add,
        search=lambda q, limit: inner.search(q, limit=limit),
        get=inner.get,
        delete=inner.delete,
    )


class FakeChroma:
    """Chroma ``Collection`` shape (``query`` nests one list per query text)."""

    def __init__(self):
        self._d = {}

    def add(self, ids, documents, metadatas=None):
        for i, mid in enumerate(ids):
            if mid in self._d:
                continue  # Chroma ignores (or rejects) duplicate ids on add.
            self._d[mid] = {
                "id": mid,
                "document": documents[i],
                "metadata": (metadatas or [None] * len(ids))[i],
            }

    def upsert(self, ids, documents, metadatas=None):
        for mid in ids:
            self._d.pop(mid, None)
        self.add(ids, documents, metadatas)

    def update(self, ids, metadatas=None, documents=None):
        for i, mid in enumerate(ids):
            if mid in self._d and metadatas is not None:
                self._d[mid]["metadata"] = metadatas[i]

    def query(self, query_texts, n_results=10, where=None, include=None):
        items = list(self._d.values())[:n_results]
        return {
            "ids": [[v["id"] for v in items]],
            "documents": [[v["document"] for v in items]],
            "metadatas": [[v["metadata"] for v in items]],
        }

    def get(self, ids=None, limit=None, offset=None, include=None):
        if ids is not None:
            items = [self._d[i] for i in ids if i in self._d]
        else:
            start = offset or 0
            items = list(self._d.values())[start : start + limit if limit else None]
        return {
            "ids": [v["id"] for v in items],
            "documents": [v["document"] for v in items],
            "metadatas": [v["metadata"] for v in items],
        }

    def delete(self, ids=None):
        for mid in ids or []:
            self._d.pop(mid, None)


def _pid(point):
    return str(point["id"] if isinstance(point, dict) else point.id)


def _selector_ids(selector):
    if isinstance(selector, dict):
        return selector.get("points") or []
    return getattr(selector, "points", None) or []


class FakeQdrant:
    """Qdrant client shape (accepts dict points or ``PointStruct``)."""

    def __init__(self):
        self._d = {}

    def upsert(self, collection_name, points):
        for point in points:
            payload = point["payload"] if isinstance(point, dict) else point.payload
            self._d[_pid(point)] = {"id": _pid(point), "payload": dict(payload)}

    def set_payload(self, collection_name, payload, points, **kw):
        for pid in points:
            if str(pid) in self._d:
                self._d[str(pid)]["payload"].update(payload)

    def scroll(self, collection_name, scroll_filter=None, limit=10, offset=None, **kw):
        items = list(self._d.values())
        start = offset or 0
        page = items[start : start + limit]
        nxt = start + limit if start + limit < len(items) else None
        return page, nxt

    def retrieve(self, collection_name, ids, **kw):
        return [self._d[str(i)] for i in ids if str(i) in self._d]

    def delete(self, collection_name, points_selector=None, **kw):
        for mid in _selector_ids(points_selector):
            self._d.pop(str(mid), None)


class FakeLlamaIndex:
    """``VectorStoreIndex`` shape: documents keyed by ``doc_id``."""

    def __init__(self):
        self.docs = {}

    def insert(self, document):
        doc_id = getattr(document, "doc_id", None) or getattr(document, "id_", None)
        self.docs[str(doc_id)] = document

    def as_retriever(self, similarity_top_k=10):
        return self

    def retrieve(self, query):
        hits = []
        for doc in self.docs.values():
            if _matches(query, getattr(doc, "text", "") or ""):
                hits.append(type("Hit", (), {"node": doc})())
        return hits[:10]

    @property
    def docstore(self):
        return self

    @property
    def ref_doc_info(self):
        return dict.fromkeys(self.docs)

    def get_document(self, doc_id):
        return self.docs.get(str(doc_id))

    def delete_ref_doc(self, doc_id, delete_from_docstore=True):
        self.docs.pop(str(doc_id), None)


class FakeVectorStore:
    """LangChain ``VectorStore`` shape (``add_texts`` upserts by id)."""

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
        return [doc for doc in self._d.values() if _matches(query, doc.page_content)][:k]

    def get_by_ids(self, ids):
        return [self._d[i] for i in ids if i in self._d]

    def delete(self, ids):
        for mid in ids or []:
            self._d.pop(mid, None)


class FakePgCursor:
    def __init__(self, rows):
        self._all = list(rows)
        self._rows = list(rows)
        self._i = 0
        self.sql = None
        self.params = None

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params
        rows = list(self._all)
        if params:
            rows = rows[: int(params[0])]
        self._rows = rows
        self._i = 0

    def fetchmany(self, n):
        chunk = self._rows[self._i : self._i + n]
        self._i += n
        return chunk

    def __iter__(self):
        return iter(self._rows[self._i :])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakePgConnection:
    """psycopg-like connection used by PgVectorScanSource tests."""

    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append(sql)

    def cursor(self, name=None):
        return FakePgCursor(self.rows)


class FakePineconeIndex:
    """Pinecone Index shape: ``list`` pages of ids, ``fetch`` by id."""

    def __init__(self, vectors):
        self._d = dict(vectors)
        self.list_calls = []
        self.fetch_calls = []

    def list(self, namespace="", limit=100):
        self.list_calls.append({"namespace": namespace, "limit": limit})
        ids = list(self._d)
        for i in range(0, max(len(ids), 1) if ids else 0, limit):
            yield ids[i : i + limit]

    def fetch(self, ids, namespace=""):
        self.fetch_calls.append(list(ids))
        return {"vectors": {i: self._d[i] for i in ids if i in self._d}}
