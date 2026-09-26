"""Model-backed checks: the semantic layer on top of the deterministic ones.

Defense in depth, cheapest first (see ``docs/research.md`` for the papers
and products each piece follows):

1. Deterministic checks (regex, offline): secrets, injection, poisoning,
   freshness, generalization. Always on, microseconds.
2. :class:`PromptGuardCheck`: local classifier (Prompt Guard 2 / PIGuard);
   no API calls, cheap enough for reads.
3. :class:`LLMJudgeCheck`: PromptArmor-style LLM detector with spotlighting
   and a memory-specific taxonomy (injection, control weakening, redirect,
   secret). Catches paraphrases, translations, and encodings.
4. :class:`LLMConflictCheck`: Mem0/Zep-style resolution against neighbours
   (duplicate / supersedes / contradicts), plus an A-MemGuard-inspired
   rule that a single write cannot silently overturn a security-relevant
   memory.
5. :class:`KnownAnswerCheck` (opt-in): DataSentinel-style behavioural
   probe.

Quick start::

    from memtrust import MemTrust
    from memtrust.checks.semantic import recommended_checks
    from memtrust.llm.openai import OpenAIClient

    guard = MemTrust(checks=recommended_checks(OpenAIClient.from_env()),
                     use_default_checks=False)
"""

from __future__ import annotations

from ...llm import LLMClient
from ..base import MemoryCheck
from ..correctness import FreshnessCheck, GeneralizationCheck
from ..security import InjectionCheck, PoisoningCheck, SecretsCheck
from ._base import ModelCheck
from .conflict import LLMConflictCheck
from .judge import LLMJudgeCheck
from .known_answer import KnownAnswerCheck
from .prompt_guard import PromptGuardCheck


def semantic_checks(
    client: LLMClient,
    *,
    judge_on_read: bool = False,
    known_answer: bool = False,
    prompt_guard: PromptGuardCheck | None = None,
) -> list[MemoryCheck]:
    """The model-backed checks only (add them to the default pipeline)."""
    checks: list[MemoryCheck] = []
    if prompt_guard is not None:
        checks.append(prompt_guard)
    checks.append(LLMJudgeCheck(client, on_read=judge_on_read))
    checks.append(LLMConflictCheck(client))
    if known_answer:
        checks.append(KnownAnswerCheck(client))
    return checks


def recommended_checks(
    client: LLMClient,
    *,
    judge_on_read: bool = False,
    known_answer: bool = False,
    prompt_guard: PromptGuardCheck | None = None,
) -> list[MemoryCheck]:
    """Full pipeline: deterministic security checks + semantic layer.

    Replaces the string-similarity duplicate/contradiction checks with
    :class:`LLMConflictCheck`. Use with ``use_default_checks=False``.
    """
    return [
        SecretsCheck(),
        InjectionCheck(),
        PoisoningCheck(),
        FreshnessCheck(),
        GeneralizationCheck(),
        *semantic_checks(
            client,
            judge_on_read=judge_on_read,
            known_answer=known_answer,
            prompt_guard=prompt_guard,
        ),
    ]


__all__ = [
    "KnownAnswerCheck",
    "LLMConflictCheck",
    "LLMJudgeCheck",
    "ModelCheck",
    "PromptGuardCheck",
    "recommended_checks",
    "semantic_checks",
]
