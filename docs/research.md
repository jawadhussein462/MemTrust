# State of the art: memory security and correctness

What the literature and the market do, and how each maps onto MemTrust's
checks. Reviewed September 2026.

## The gap MemTrust sits in

Two groups solve half the problem each:

* **Guardrail products** (Lakera Guard, Azure Prompt Shields, Prompt Guard,
  PIGuard, LLM Guard, NeMo Guardrails) classify a *prompt* in isolation.
  They do not know about memory: no lifecycle, no neighbours, no notion that
  a benign-looking fact can overturn an existing one.
* **Memory systems** (Mem0, Zep/Graphiti) resolve new facts against existing
  ones with an LLM, but they optimise for recall and consistency, not
  safety: an attacker's "update" is applied like any other.

A-MemGuard reports that even advanced LLM-based detectors miss 66% of
poisoned memory entries when each entry is audited in isolation. The effect
of a poisoned memory only shows up in context. So the useful place for a
defence is where the two meet: at write and read time, judging content
**and** its relation to what is already remembered.

## Techniques and where they are used

| Technique | Source | MemTrust | Notes / limits |
|---|---|---|---|
| LLM as injection detector | PromptArmor (Shi et al. 2025, [arXiv:2507.15219](https://arxiv.org/abs/2507.15219)): off-the-shelf GPT-4o / GPT-4.1 / o4-mini reach <1% FPR and FNR on AgentDojo | `LLMJudgeCheck` | Extended with memory-specific flags: control weakening, destination redirect, secret. |
| Spotlighting (delimiting) | Hines et al. 2024, Microsoft ([paper](https://www.microsoft.com/en-us/research/publication/defending-against-indirect-prompt-injection-attacks-with-spotlighting/)); used in Azure Prompt Shields | `memtrust.llm.spotlight` wraps all untrusted text in random tags | Datamarking and encoding variants not used; strict JSON output removes the free-text channel instead. |
| Schema-constrained verdicts | OpenAI Structured Outputs (`json_schema`, `strict: true`) | `OpenAIClient.complete_json` | Injected text cannot produce a non-conforming "SAFE" answer. |
| Known-answer detection | Liu et al., USENIX Security 2024; DataSentinel (Liu et al., IEEE S&P 2025, [arXiv:2504.11358](https://arxiv.org/abs/2504.11358)) | `KnownAnswerCheck` (opt-in) | Uses an off-the-shelf model. DataSentinel's minimax fine-tuning, which is what makes it robust to adaptive attacks, is not reproduced. |
| Small injection classifiers | Llama Prompt Guard 2 86M ([model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)); PIGuard / InjecGuard ([model](https://huggingface.co/leolee99/PIGuard)), trained against over-defense and evaluated on NotInject | `PromptGuardCheck` (local, runs on reads) | Prompt Guard 2 is gated. Controlled-release prompting has bypassed production prompt guards ([arXiv:2510.01529](https://arxiv.org/pdf/2510.01529)), so it is one layer, not the defence. |
| LLM update phase (ADD / UPDATE / DELETE / NOOP) | Mem0 (Chhikara et al. 2025, [arXiv:2504.19413](https://arxiv.org/abs/2504.19413)) | `LLMConflictCheck` relations → duplicate / supersede / contradiction | MemTrust never deletes: superseded records stay, hidden from reads. |
| Temporal edge invalidation, bi-temporal history | Zep / Graphiti (Rasmussen et al. 2025, [arXiv:2501.13956](https://arxiv.org/abs/2501.13956)) | `SUPERSEDED` status plus `valid_from` / `valid_until` | Single ingestion timestamp; no separate "valid time" extraction yet. |
| Consensus with related memories | A-MemGuard ([arXiv:2510.02373](https://arxiv.org/abs/2510.02373)): consensus-based validation over parallel reasoning paths, plus a separate store of lessons | `unverified_security_change`: a write that supersedes or contradicts a security-relevant memory is held for review | A lightweight approximation at write time; the full reasoning-path consensus at query time is not implemented. |
| Memory injection through queries | MINJA (memory injection via ordinary interactions) | Motivates reviewing security-relevant "updates" instead of applying them | — |
| RAG knowledge poisoning | PoisonedRAG ([arXiv:2402.07867](https://arxiv.org/abs/2402.07867)) | Read-time checks; `destination_redirect`; `memory_poisoning` | Clustering/aggregation defences (TrustRAG [arXiv:2501.00879](https://arxiv.org/abs/2501.00879), RobustRAG) act on the retrieved set, not on single memories; a possible read-time extension. |
| Activation-based detection | RevPRAG ([ACL Findings 2025](https://aclanthology.org/2025.findings-emnlp.698/)) | Not used | Needs white-box access to the generator; not possible behind an API. |
| Post-hoc attribution | MemAudit ([arXiv:2605.23723](https://arxiv.org/abs/2605.23723)) | Not used; `scan()` and `revoke()` are the audit primitives | A natural fit for the lineage (`derived_from`) MemTrust already stores. |

## Products

| Product | What it is | Relation to MemTrust |
|---|---|---|
| Lakera Guard (Check Point) | SaaS prompt-injection API, many languages, low latency | Could be wrapped as a check; no memory semantics. |
| Azure Prompt Shields | Injection/jailbreak detection in Azure AI Content Safety; uses spotlighting | Same as above, Azure-only. |
| Llama Prompt Guard 2, PIGuard | Open classifiers | Bundled as `PromptGuardCheck`. |
| LLM Guard (Protect AI → Palo Alto Networks) | Open-source scanners; reported archived in 2026 | Superseded by the layers above. |
| NVIDIA NeMo Guardrails | Dialogue rails (Colang) | Conversation flow, not memory. |
| Mem0, Zep | Memory stores with LLM conflict resolution | MemTrust wraps them as backends and adds the safety gate they lack. |

## Pipeline

```text
write ─▶ secrets · injection · poisoning (regex, offline, µs)
      ─▶ PromptGuardCheck (local model, optional)
      ─▶ LLMJudgeCheck (spotlighted, strict JSON)
      ─▶ LLMConflictCheck vs. nearest neighbours (supersede / review / duplicate)
      ─▶ KnownAnswerCheck (optional)
      ─▶ aggregate: most protective action wins; a failing model degrades to the
         deterministic layer (on_error="open") or blocks (on_error="closed")
read  ─▶ lifecycle filters ─▶ regex security checks ─▶ PromptGuard / judge if on_read
```

## Measuring it

`python benchmarks/eval_detectors.py` reports attack recall and benign false
positives on the regression corpus, the known misses, a held-out set, and
conflict pairs, for the deterministic pipeline and, with `OPENAI_API_KEY`
set, the LLM pipeline. The corpora are small and hand-written, so they show
regressions, not absolute accuracy. Before relying on the numbers, evaluate
on public sets: AgentDojo, NotInject (over-defense), and PoisonedRAG /
AgentPoison / MINJA-style memory attacks.
