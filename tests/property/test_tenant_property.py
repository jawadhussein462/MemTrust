"""Property-based tests for the tenant isolation boundary."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from memtrust import MemTrust, MemoryRecord, Scope

_TENANTS = st.sampled_from(["acme", "globex", "initech", "umbrella"])

_records = st.lists(
    st.builds(
        MemoryRecord,
        id=st.text(min_size=1, max_size=6),
        content=st.text(min_size=1, max_size=40),
        scope=st.builds(Scope, tenant_id=_TENANTS),
    ),
    max_size=8,
)


@given(mem_tenant=_TENANTS, req_tenant=_TENANTS, content=st.text(min_size=1, max_size=40))
def test_read_matches_only_same_tenant(mem_tenant, req_tenant, content):
    guard = MemTrust()
    record = MemoryRecord(id="m", content=content, scope=Scope(tenant_id=mem_tenant))
    result = guard.check_read([record], scope={"tenant_id": req_tenant})
    if mem_tenant == req_tenant:
        assert len(result.results) == 1
    else:
        assert result.results == []


@given(records=_records, req_tenant=_TENANTS)
def test_no_returned_record_is_cross_tenant(records, req_tenant):
    guard = MemTrust()
    result = guard.check_read(records, scope={"tenant_id": req_tenant})
    for safe in result.results:
        assert safe.record.scope.tenant_id == req_tenant
