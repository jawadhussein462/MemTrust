"""Read-only scan sources: chroma, qdrant, pgvector, pinecone."""

from __future__ import annotations

import pytest

from memorysec.exceptions import ConfigurationError
from memorysec.scan.chroma import ChromaScanSource
from memorysec.scan.pgvector import PgVectorScanSource
from memorysec.scan.pinecone import PineconeScanSource
from memorysec.scan.qdrant import QdrantScanSource
from memorysec.scan.source import quote_ident
from tests.fakes import FakeChroma, FakePgConnection, FakePineconeIndex, FakeQdrant


def test_chroma_streams_and_samples():
    handle = FakeChroma()
    handle.upsert(
        ids=["a", "b", "c"],
        documents=["one", "two", "three"],
        metadatas=[{}, {}, {}],
    )
    src = ChromaScanSource(handle=handle)
    records = list(src.records(batch_size=2, sample=2))
    assert [r.id for r in records] == ["a", "b"]
    assert records[0].content == "one"


def test_qdrant_is_read_only_scroll():
    client = FakeQdrant()
    client.upsert(
        "agent_memory",
        [{"id": "p1", "payload": {"content": "Alice prefers tea."}}],
    )
    src = QdrantScanSource(client=client, collection="agent_memory")
    records = list(src.records())
    assert records[0].id == "p1" and "tea" in records[0].content


def test_pgvector_selects_and_honours_sample_and_read_only():
    conn = FakePgConnection(
        [
            ("m1", "Alice prefers tea."),
            ("m2", "Bob sits in Berlin."),
            ("m3", "Carol likes coffee."),
        ]
    )
    src = PgVectorScanSource(
        connection=conn,
        table="memories",
        text_column="content",
        id_column="id",
    )
    records = list(src.records(batch_size=2, sample=2))
    assert [r.id for r in records] == ["m1", "m2"]
    assert any("READ ONLY" in s.upper() for s in conn.statements)


def test_pgvector_rejects_unsafe_identifiers():
    with pytest.raises(ConfigurationError, match="identifier"):
        PgVectorScanSource(
            connection=FakePgConnection([]),
            table="memories; drop table memories",
            text_column="content",
        )
    assert quote_ident("public.memories") == '"public"."memories"'


def test_pinecone_lists_then_fetches_metadata():
    index = FakePineconeIndex(
        {
            "v1": {"metadata": {"text": "Alice prefers tea."}},
            "v2": {"metadata": {"content": "Bob sits in Berlin."}},
        }
    )
    src = PineconeScanSource(handle=index, namespace="prod")
    records = {r.id: r.content for r in src.records(batch_size=1, sample=2)}
    assert records["v1"] == "Alice prefers tea."
    assert records["v2"] == "Bob sits in Berlin."
    assert index.list_calls[0]["namespace"] == "prod"
    assert index.fetch_calls


def test_missing_connection_args():
    with pytest.raises(ConfigurationError):
        ChromaScanSource()
    with pytest.raises(ConfigurationError):
        QdrantScanSource(collection="x")
    with pytest.raises(ConfigurationError):
        PgVectorScanSource(table="t", text_column="c")
    with pytest.raises(ConfigurationError):
        PineconeScanSource()
