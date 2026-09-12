"""Policy engine: declarative rules, callables, and precedence."""

from __future__ import annotations

from memtrust import Finding, MemTrust, Policy
from memtrust.policies.builtin import NO_SSN


def test_declarative_forbidden_substrings():
    guard = MemTrust(policies=[NO_SSN])
    decision = guard.check_write("Customer SSN is on file.")
    assert not decision.allowed
    assert "no-ssn" in decision.policy_matches
    assert "policy_content_violation" in decision.finding_codes()


def test_declarative_when_metadata():
    policy = Policy(
        name="tagged-block",
        when={"env": "production"},
        require={"forbidden_substrings": ["password"]},
    )
    guard = MemTrust(policies=[policy])
    from memtrust import MemoryCandidate

    tagged = MemoryCandidate(content="the password is x", metadata={"env": "production"})
    decision = guard.check_write(tagged)
    assert "policy_content_violation" in decision.finding_codes()

    untagged = MemoryCandidate(content="the password is x", metadata={"env": "dev"})
    # Secrets check still redacts, but the policy should not match.
    decision2 = guard.check_write(untagged)
    assert "tagged-block" not in decision2.policy_matches


def test_callable_policy():
    def block_pii(candidate, context):
        if "ssn" in candidate.content.lower():
            return Finding(
                code="pii_policy",
                category="security",
                severity="high",
                message="No SSNs.",
                recommended_action="block",
            )
        return None

    guard = MemTrust(policies=[block_pii])
    decision = guard.check_write("Customer SSN is on file.")
    assert not decision.allowed
    assert "pii_policy" in decision.finding_codes()


def test_high_precedence_action_wins():
    def hard_block(candidate, context):
        return Finding(
            code="hard",
            severity="critical",
            category="security",
            message="nope",
            recommended_action="block",
        )

    guard = MemTrust(policies=[hard_block])
    decision = guard.check_write("anything")
    assert decision.recommended_action.value == "block"
    assert not decision.allowed
