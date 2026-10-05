"""In-process fakes of provider SDKs used by scan-source tests."""

from __future__ import annotations


class FakeChroma:
    """Chroma ``Collection`` shape (``query`` nests one list per query text)."""

    def __init__(self):
        self._d = {}

    def add(self, ids, documents, metadatas=None):
        for i, mid in enumerate(ids):
            if mid in self._d:
                continue
            self._d[mid] = {
                "id": mid,
                "document": documents[i],
                "metadata": (metadatas or [None] * len(ids))[i],
            }

    def upsert(self, ids, documents, metadatas=None):
        for mid in ids:
            self._d.pop(mid, None)
        self.add(ids, documents, metadatas)

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


def _pid(point):
    return str(point["id"] if isinstance(point, dict) else point.id)


class FakeQdrant:
    """Qdrant client shape (accepts dict points)."""

    def __init__(self):
        self._d = {}

    def upsert(self, collection_name, points):
        for point in points:
            payload = point["payload"] if isinstance(point, dict) else point.payload
            self._d[_pid(point)] = {"id": _pid(point), "payload": dict(payload)}

    def scroll(self, collection_name, scroll_filter=None, limit=10, offset=None, **kw):
        items = list(self._d.values())
        start = offset or 0
        page = items[start : start + limit]
        nxt = start + limit if start + limit < len(items) else None
        return page, nxt


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
