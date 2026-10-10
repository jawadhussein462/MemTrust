# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

MemorySec 0.1.0 was an SDK that sat between an agent and its memory backend
(the project was called MemTrust then). Since then it has become a scanner:
it reads a memory store, reports poisoned facts, hidden instructions, and
leaked secrets, and recommends what to do with each record. It never writes
to the store. Everything below is relative to 0.1.0.

### Added

- **Store scanning.** `MemorySec().scan(source)` and `memorysec scan
  chroma|qdrant|pgvector|pinecone|jsonl|langchain|mem0`. Sources are
  read-only and stream records in batches; `--sample N` caps a scan.
- **LangChain, LangGraph, and mem0 sources.** `LangChainScanSource` reads
  LangChain vector stores (InMemoryVectorStore, Chroma, Qdrant, Pinecone,
  FAISS, PGVector, or any store by id with `get_by_ids`);
  `LangGraphStoreScanSource` reads a LangGraph `BaseStore` (LangGraph and
  LangMem long-term memory); `Mem0ScanSource` reads mem0's open-source
  `Memory` (whole store or one user/agent/run) and the hosted
  `MemoryClient`. CLI: `scan langchain --factory module:attr`,
  `scan mem0 --config FILE | --api-key KEY`. Extras: `langchain`,
  `langgraph`, `mem0`.
- **Reports.** A self-contained HTML report (verdict, triage plan,
  findings with masked excerpts, fix steps, OWASP and CWE links), JSON
  (`--json`, schema `1.2`), SARIF 2.1.0 (`--sarif`) for GitHub code
  scanning, and Markdown (`--markdown`) for job summaries and PR comments.
  Every format uses the rule catalogue in `memorysec.rules` and stable
  per-finding `fingerprint`s.
- **CI gates.** `--fail-on SEVERITY` exits `1` when a finding reaches that
  severity; `--min-confidence SCORE` ignores weaker findings for that gate;
  `-q` prints counts only.
- **Confidence.** Every finding has a `confidence` from 0 to 1: the
  combined score of the detectors that agreed on it (`1 - Π(1 - score)`).
  A finding below 0.6 is reported one severity step lower.
- **Detectors.** Each check runs a list of detectors and can require
  several to agree (`min_detectors`). Opt-in detectors: Hugging Face
  classifiers (Prompt Guard 2, Protect AI and deepset DeBERTa, Sentinel,
  Piiranha, StarPII), GLiNER, Presidio, detect-secrets, Azure Prompt
  Shields, Lakera Guard, entropy, known-answer and DataSentinel, embedding
  classifiers, perplexity and RAGuard, TrustRAG, hubness, embedding
  consistency, temporal NLI, probe queries, and live secret verification.
- **Scan errors.** `ScanReport.errors`, `complete`, and
  `records_with_errors` say which checks or detectors failed and on how
  many records.
- **`WriteGuard` and `RetrieveGuard`** (`memorysec.integrations`): run the
  scan on a memory before it is written, or on records just retrieved for a
  query. They replace 0.1.0's `check_write` / `check_read`.
- **Accuracy benchmark** (`benchmarks/`): the default detectors measured on
  public datasets they were not written against (GitHub's help articles,
  AgentDojo, BIPIA, InjecAgent, PoisonedRAG), with a held-out test split.
  Results are in `benchmarks/RESULTS.md`.
- **`memorysec.corpus`**: the packed record store and shared
  nearest-neighbour table corpus detectors use, with a pluggable
  `NeighbourIndex`. The `fast` extra installs numpy for the exact index.
- OpenTelemetry tracing (`memorysec[otel]`) and loguru logging; MemorySec
  never adds or removes log sinks.

### Changed

- **Default detectors are scored and read context.** The injection and
  poisoning heuristics judge each match by its sentence: help-text framing
  ("To disable 2FA, go to Settings"), conditionals, questions, limited
  scope ("guest Wi-Fi", "when on VPN"), advice, and quotations lower the
  score; sensitive assets, change markers, and directives aimed at the agent
  raise it; a prohibition ("never disable MFA") drops the match. Bare
  "review", "login", and "password" count only weakly. New coverage:
  paraphrased overrides, typos in trigger words, base64/hex/URL/HTML/
  reversed payloads, fake role tokens, task hijacking, authority spoofing,
  limit removal, data exfiltration, secrets pushed into channels, and links
  or falsehoods pushed into the agent's replies.
- **Severities follow one rule.** Explicit attack text is high
  (`persistent_instruction`, `memory_poisoning`, `destination_redirect`);
  model or behavioural evidence is medium (`known_answer`,
  `embedding_injection`, `adversarial_text`, `embedding_mismatch`,
  `temporal_contradiction`, `retrieval_flip`, `pii_detected`); corpus
  statistics are low (`poisoning_cluster`, `hub_record`); a leaked secret
  is critical.
- **A failing detector marks the scan incomplete.** It used to become a
  critical `check_error` finding with action `delete` on every record. Now
  the healthy detectors' results are kept, the failure is listed in
  `report.errors`, no finding is created, and the CLI exits `2` (unless
  `--allow-incomplete`). SARIF sets `executionSuccessful: false`; the HTML
  and Markdown reports say the scan is incomplete. With `fail_closed=True`
  (the default) `WriteGuard` refuses and `RetrieveGuard` drops records that
  were not fully checked.
- **Scans stream.** Records are no longer collected into one list. Text
  detectors run as records arrive; corpus detectors (TrustRAG, hubness,
  NLI) run afterwards against packed float32 vectors and one shared k-NN
  table. 50,000 records with 1,536-dimension vectors scan in about 90
  seconds and 1.1 GB. TrustRAG's `embed=` path embeds each text once per
  scan, and its lexical fallback compares records that share rare word
  pairs instead of every pair.
- `AsyncMemorySec.scan` runs in a worker thread so it no longer blocks the
  event loop, and accepts async iterables.
- `MemorySec(checks=[...])` replaces a default check with the same name.

### Removed

- The write/read SDK: `check_write`, `check_read`, `protect`,
  `ProtectedMemory`, `AsyncProtectedMemory`, `revoke_source`, `Decision`,
  `ReadResult`, `SafeMemory`, `FilteredMemory`, `RevocationReport`, gate
  actions (`allow`, `allow_with_warning`, `block`), modes (`observe`,
  `warn`, `enforce`), and the `memorysec check` and `memorysec audit`
  commands. Use `MemorySec.scan`, or `WriteGuard` / `RetrieveGuard` on the
  write and read paths.
- Backends and adapters: `MemoryBackend`, `InMemoryBackend`,
  `FunctionBackend`, the Mem0 and LangGraph adapters, and the `zep`
  extra. Scan sources are the only store integrations.
- Correctness checks (contradiction, duplication, freshness,
  generalization), source/scope/tenant/authority models and checks,
  policies, the audit trail, secret redaction, the injectable clock, the
  provenance model, and the semantic analyzer.
- The `check_error` finding code.

### Fixed

- `memorysec scan chroma` failed on any collection with stored vectors:
  chromadb returns embeddings as a numpy array, which the source tested
  with `or`.
- pgvector vectors returned as text (`"[0.1,0.2]"`, without the pgvector
  adapter) were dropped, which silently turned the vector detectors off.
- `HubnessDetector` cached its table without its `k`, so two hubness
  detectors with different `k` shared one result.
- `WriteGuard` put a detector name in `Finding.check`.
- A reset link after "password:" was reported as a leaked password.

## [0.1.0] - 2026-09-12

Initial public release. MemorySec v0.1 is an SDK/MVP: a vendor-neutral trust
boundary between an AI agent and its memory backend.

### Added

- **Facade**: `MemorySec` and `AsyncMemorySec` with `check_write`, `check_read`,
  `protect`, and `revoke_source`.
- **Domain models** (Pydantic v2): `Source`, `Scope`, `MemoryCandidate`,
  `MemoryRecord`, `Finding`, `Decision`, `Provenance`, `Policy`, plus enums for
  trust, severity, risk, action, status, and memory relationships.
- **Authority vs. confidence**: modeled as distinct fields, with authority
  derived from source trust by default.
- **Security checks**: persistent-instruction/injection detection, secret
  detection with redaction, tenant isolation, scope-promotion detection, and a
  low-authority policy-write check (`untrusted_policy_write`).
- **Correctness checks**: freshness/expiry, local duplicate detection,
  contradiction vs. supersession, and a generalization extension point.
- **Core enforcement** that cannot be bypassed by customizing the check list:
  cross-tenant/cross-user read isolation, tenant-match on write, and filtering
  of revoked/expired/quarantined/superseded records.
- **Policies**: declarative `Policy` (`when`/`require`) plus plain callables.
- **Semantic strategy**: deterministic `HeuristicSemanticAnalyzer` (default,
  offline) and an optional provider-agnostic `LLMSemanticAnalyzer` with
  timeouts and fail-open/closed behavior.
- **Backends**: `MemoryBackend`/`AsyncMemoryBackend` Protocols and in-memory
  reference implementations; adapters for Mem0 and LangGraph `BaseStore`; a
  generic `FunctionBackend`.
- **Audit**: JSON-serializable `AuditEvent`, `InMemoryAuditStore`, and
  `JSONLAuditStore`. Secrets are redacted from audit content.
- **Telemetry**: stdlib `logging` (no `basicConfig`) and optional OpenTelemetry
  tracing (injected, never global).
- **Modes**: `observe`, `warn`, `enforce` (default).
- **CLI**: `memorysec check` and `memorysec audit`.
- Test suite (unit, integration, security-invariant, property-based) and six
  runnable examples.

[Unreleased]: https://github.com/jawadhussein462/MemorySec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jawadhussein462/MemorySec/releases/tag/v0.1.0
