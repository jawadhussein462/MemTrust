"""Heuristic semantic analyzer relationship classification."""

from __future__ import annotations

from datetime import timedelta

from memtrust._time import utcnow
from memtrust.models.enums import MemoryRelationship
from memtrust.semantic.heuristic import HeuristicSemanticAnalyzer

from tests.factories import make_candidate, make_record


def test_identical_is_duplicate():
    a = HeuristicSemanticAnalyzer()
    existing = make_record("Alice prefers annual billing.", user="alice")
    cand = make_candidate("Alice prefers annual billing.", user="alice")
    assert a.compare(existing, cand) is MemoryRelationship.DUPLICATE


def test_newer_value_supersedes():
    a = HeuristicSemanticAnalyzer()
    existing = make_record("Alice works at Stripe.", user="alice")
    existing.created_at = utcnow() - timedelta(days=5)
    cand = make_candidate("Alice now works at Anthropic.", user="alice")
    assert a.compare(existing, cand) is MemoryRelationship.SUPERSEDES


def test_polarity_flip_contradicts_when_not_newer():
    a = HeuristicSemanticAnalyzer()
    existing = make_record("Refunds require approval.", user="alice")
    cand = make_candidate("Refunds do not require approval.", user="alice")
    cand.created_at = existing.created_at  # same time, no temporal marker
    assert a.compare(existing, cand) is MemoryRelationship.CONTRADICTS


def test_different_user_is_different_scope():
    a = HeuristicSemanticAnalyzer()
    existing = make_record("Prefers window seat.", user="alice")
    cand = make_candidate("Prefers aisle seat.", user="bob")
    assert a.compare(existing, cand) is MemoryRelationship.DIFFERENT_SCOPE


def test_unrelated():
    a = HeuristicSemanticAnalyzer()
    existing = make_record("The sky is blue today.", user="alice")
    cand = make_candidate("Quarterly revenue rose 3 percent.", user="alice")
    assert a.compare(existing, cand) is MemoryRelationship.UNRELATED


def test_detect_generalization():
    a = HeuristicSemanticAnalyzer()
    cand = make_candidate(
        "User always wants to skip staging.",
        excerpt="For this migration only, skip staging.",
    )
    assert a.detect_generalization(cand) is True
    plain = make_candidate("User is called Alice.", excerpt="Hi, my name is Alice.")
    assert a.detect_generalization(plain) is False
