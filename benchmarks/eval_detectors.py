"""Compare the deterministic pipeline with the LLM-backed one.

    cp .env.example .env   # add OPENAI_API_KEY
    python benchmarks/eval_detectors.py

Without a key only the deterministic rows are printed. Sets come from
tests/corpus.py: the regression corpus, KNOWN_MISSES, a held-out set that
was never used for tuning, and conflict-resolution pairs. Costs a few cents
with gpt-5-mini (~100 short calls).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import corpus

from memtrust import MemoryRecord, MemTrust
from memtrust.checks.semantic import recommended_checks
from memtrust.exceptions import IntegrationError

SECURITY = {
    "persistent_instruction",
    "memory_poisoning",
    "destination_redirect",
    "secret_detected",
    "unverified_security_change",
}
ATTACKS = corpus.INJECTION + corpus.POISONING + corpus.SECRETS


def _flagged(guard: MemTrust, text: str) -> bool:
    return bool(set(guard.check_write(text).finding_codes()) & SECURITY)


def _rate(guard: MemTrust, texts: list[str]) -> str:
    hits = sum(_flagged(guard, t) for t in texts)
    return f"{hits}/{len(texts)}"


def _conflict_outcome(guard: MemTrust, old: str, new: str) -> str:
    existing = MemoryRecord(id="existing", content=old)
    codes = set(guard.check_write(new, existing=[existing]).finding_codes())
    if codes & {"contradiction", "unverified_security_change"} or codes & SECURITY:
        return "review"
    if "supersedes_existing" in codes:
        return "supersede"
    if "duplicate_memory" in codes:
        return "duplicate"
    return "none"


def evaluate(name: str, guard: MemTrust) -> None:
    start = time.perf_counter()
    conflicts = sum(
        _conflict_outcome(guard, old, new) == want for old, new, want in corpus.CONFLICTS
    )
    row = [
        name,
        _rate(guard, ATTACKS),
        _rate(guard, corpus.BENIGN),
        _rate(guard, corpus.KNOWN_MISSES),
        _rate(guard, corpus.HELDOUT_ATTACKS),
        _rate(guard, corpus.HELDOUT_BENIGN),
        f"{conflicts}/{len(corpus.CONFLICTS)}",
        f"{time.perf_counter() - start:.1f}s",
    ]
    print(" | ".join(f"{c:>13}" for c in row))


def main() -> int:
    header = [
        "pipeline",
        "attacks",
        "benign FP",
        "known misses",
        "held-out atk",
        "held-out FP",
        "conflicts",
        "time",
    ]
    print(" | ".join(f"{h:>13}" for h in header))
    evaluate("deterministic", MemTrust())
    try:
        from memtrust.llm.openai import OpenAIClient

        client = OpenAIClient.from_env()
    except IntegrationError as exc:
        print(f"\n(skipping LLM pipeline: {exc})")
        return 0
    evaluate(client.model, MemTrust(checks=recommended_checks(client), use_default_checks=False))
    evaluate(
        f"{client.model}+KA",
        MemTrust(checks=recommended_checks(client, known_answer=True), use_default_checks=False),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
