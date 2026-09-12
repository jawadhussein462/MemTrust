"""Property-based round-trip serialization for core models."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from memtrust import MemoryRecord, Scope, Source
from memtrust.models.enums import MemoryStatus, TrustLevel

_TRUST = st.sampled_from([t.value for t in TrustLevel])
_STATUS = st.sampled_from([s.value for s in MemoryStatus])


@given(
    content=st.text(max_size=80),
    tenant=st.text(min_size=1, max_size=10),
    trust=_TRUST,
    status=_STATUS,
    authority=st.floats(min_value=0.0, max_value=1.0),
)
def test_record_json_round_trip(content, tenant, trust, status, authority):
    record = MemoryRecord(
        id="m",
        content=content,
        source=Source(type="conversation", trust=trust),
        scope=Scope(tenant_id=tenant),
        trust=trust,
        status=status,
        authority=authority,
    )
    restored = MemoryRecord.model_validate_json(record.model_dump_json())
    assert restored.content == record.content
    assert restored.scope.tenant_id == record.scope.tenant_id
    assert restored.trust == record.trust
    assert restored.status == record.status
