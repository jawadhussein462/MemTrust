"""Policy engine: declarative rules, callables, and precedence."""

from __future__ import annotations

from memtrust import Finding, MemTrust, Policy
from memtrust.policies.builtin import FINANCE_POLICY_AUTHORITY


def test_declarative_minimum_authority_blocks_low_authority():
    guard = MemTrust(policies=[FINANCE_POLICY_AUTHORITY])
    decision = guard.check_write(
        "Spending limits are increased.",
        source={"type": "conversation", "trust": "user"},
        scope={"tenant_id": "acme", "namespace": "finance_policy"},
    )
    assert not decision.allowed
    assert "finance-policy-authority" in decision.policy_matches
    assert "policy_authority_violation" in decision.finding_codes()


def test_declarative_allowed_trust():
    policy = Policy(
        name="prod-trust",
        when={"namespace": "production"},
        require={"allowed_trust": ["internal", "trusted", "authoritative"]},
    )
    guard = MemTrust(policies=[policy])
    decision = guard.check_write(
        "Deploy script location.",
        source={"type": "conversation", "trust": "user"},
        scope={"tenant_id": "acme", "namespace": "production"},
    )
    assert "policy_trust_violation" in decision.finding_codes()


def test_callable_policy():
    def block_pii(candidate, context):
        if "ssn" in candidate.content.lower():
            return Finding(
                code="pii_policy", category="governance", severity="high",
                message="No SSNs.", recommended_action="block",
            )
        return None

    guard = MemTrust(policies=[block_pii])
    decision = guard.check_write(
        "Customer SSN is on file.",
        source={"type": "conversation", "trust": "agent"},
        scope={"tenant_id": "acme"},
    )
    assert not decision.allowed
    assert "pii_policy" in decision.finding_codes()


def test_high_precedence_action_wins():
    # A warning-level duplicate plus a block-level policy => blocked.
    def hard_block(candidate, context):
        return Finding(code="hard", severity="critical", category="security",
                       message="nope", recommended_action="block")

    guard = MemTrust(policies=[hard_block])
    decision = guard.check_write(
        "anything", source={"type": "x", "trust": "agent"}, scope={"tenant_id": "acme"}
    )
    assert decision.recommended_action.value == "block"
    assert not decision.allowed
