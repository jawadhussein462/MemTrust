# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Security + correctness only**: MemTrust is now oriented around two check
  families. **Security** detects poisoning, injection, and secrets.
  **Correctness** detects contradictions, duplicates, freshness, and
  over-generalization. Built-in checks live under
  `memtrust.checks.security` and `memtrust.checks.correctness`.
- **Simplified API**: `check_write(content)`, `check_read(records)`,
  `protect(...).add(content)` / `.search(query)` — no `source`, `scope`,
  `tenant`, `trust`, or `authority` arguments.
- **Poisoning is content-based**: `PoisoningCheck` flags false
  security-relevant facts (disabled auth, attacker hosts, approval bypasses)
  instead of gating writes on source trust / authority.
- **Revocation** is `revoke(memory_id)` (a memory and anything derived from
  it), replacing `revoke_source`.

### Removed

- Source, scope, tenant, and authority models (`Source`, `Scope`,
  `TrustLevel`, `effective_authority`).
- `AuthorityCheck`, `ScopeCheck`, `TenantCheck`, and core cross-tenant /
  cross-user isolation.
- Governance as a finding category.
- Example `02_cross_tenant_read.py` (replaced by injection) and
  `07_user_ltm_vs_shared_knowledge.py` (replaced by secret detection).
- Experimental `ZepBackend` and the `zep` extra.
- Audit trail: `AuditEvent`, `AuditStore`, `InMemoryAuditStore`,
  `JSONLAuditStore`, `AuditEventType`, `audit_store`, `audit_content` config,
  and the `memtrust audit` CLI.
- Policies: `Policy`, `PolicyEngine`, `PolicyCallable`, `PolicyError`,
  `policy_matches`, `MemTrust(policies=...)`, and the `memtrust.policies`
  package. Domain rules belong in custom checks.
- Injectable clock: `Clock`, `SystemClock`, `FixedClock`, and the
  `clock=` constructor argument. Evaluation uses wall-clock UTC.
- Secret redaction: `memtrust.redaction`, `redact_secrets`, `Action.REWRITE`,
  `Decision.rewritten_content`, and example `07_secret_redaction.py`.
  Secret-bearing writes are blocked; findings report kinds only.
- Enforcement modes: `Mode`, `observe` / `warn` / `enforce`, `Config.mode`,
  `MemTrust(mode=...)`, `Decision.mode`, and `Decision.enforced`. Decisions
  always apply the recommended action.
- Semantic analyzer: `memtrust.semantic`, `SemanticAnalyzer`,
  `HeuristicSemanticAnalyzer`, `LLMSemanticAnalyzer`, `openai_completer`,
  `MemTrust(semantic_analyzer=...)`, `Config.llm_timeout`,
  `Config.semantic_fail_open`, `Config.semantic_neighbor_limit` (renamed
  `neighbor_limit`), the `openai` extra, and `SPAN_SEMANTIC_COMPARE`.
  Contradiction, supersession, and generalization checks now use local
  heuristics directly.
- Provenance model: `Provenance`, `Retrieval`, `MemoryRecord.provenance`,
  and `SafeMemory.provenance`. Lineage is `derived_from` on the record.
- Time helper module `memtrust._time` (`utcnow`, `ensure_aware`).
- Shared adapter codec `memtrust.integrations._codec` (`encode_record`,
  `decode_record`). RAG adapters store document text by id.

### Added

- **RAG adapters**: `ChromaBackend`, `QdrantBackend`, `LlamaIndexBackend`, and
  `LangChainVectorStoreBackend`, plus extras `chroma`, `qdrant`, `llamaindex`,
  and `langchain`.
- Example `02_injection.py` and `07_secret_detection.py`.

### Fixed

- **Security: RAG adapters served quarantined, superseded, and revoked
  memories.** `ChromaBackend`, `QdrantBackend`, `LlamaIndexBackend`, and
  `LangChainVectorStoreBackend` stored only id + text, so every record came
  back `ACTIVE`: a quarantined poisoning attempt was returned by `search()`,
  and superseded facts kept surfacing. Record state (status, validity window,
  lineage, metadata) now round-trips through store metadata/payload via the
  shared `memtrust.integrations._codec`; unreadable state fails closed as
  `QUARANTINED`.
- **Status changes duplicated records.** Every shipped adapter now implements
  `set_status` in place (Chroma `update`, Qdrant `set_payload`, Mem0
  `update(metadata=...)`, LangGraph `put`, LlamaIndex/LangChain replace by
  id). The generic fallback deletes the stale copy when a backend assigns a
  new id instead of upserting.
- **Qdrant adapter crashed against the real client** (plain-dict points,
  non-UUID ids). It now sends `PointStruct`s and maps MemTrust ids to stable
  UUIDv5 point ids. Keyword-only mode ranks by similarity instead of
  substring match, so write-time neighbour lookup finds related facts.
- **LlamaIndex adapter** returned node UUIDs instead of MemTrust ids, so
  `get()` and supersession targeted the wrong records. The state JSON is
  excluded from embedding and LLM text.
- **Mem0 2.x**: identity (`user_id` / `agent_id` / `run_id`) is now passed
  where each client expects it (top-level on OSS `add`, inside `filters` on
  search and platform add), with `top_k` vs. `limit` chosen by signature.
- **LangGraph adapter** `get`/`delete` read by key instead of scanning the
  first 1000 items; a `namespace` argument allows per-user namespaces.
- Revocation from a fresh guard: adapters implement `all()`
  (`SupportsListing`), so lineage is read from the store rather than only
  the in-process index.
- **Mem0 platform adapter**: `MemoryClient` v2+ rejects top-level `user_id` on
  search (requires `filters` + `top_k`), returns `PENDING` with no memory id
  when `infer=True`, and flattens nested metadata on some endpoints. The
  adapter now auto-detects platform clients, stores records as-is
  (`infer=False`), keeps the record as a JSON metadata string, and treats
  invalid `get` ids as a miss.

## [0.1.0] - 2026-09-12

Initial public release. MemTrust v0.1 is an SDK/MVP: a vendor-neutral trust
boundary between an AI agent and its memory backend.

### Added

- **Facade**: `MemTrust` and `AsyncMemTrust` with `check_write`, `check_read`,
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
- **CLI**: `memtrust check` and `memtrust audit`.
- Test suite (unit, integration, security-invariant, property-based) and six
  runnable examples.

[Unreleased]: https://github.com/memtrust/memtrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/memtrust/memtrust/releases/tag/v0.1.0
