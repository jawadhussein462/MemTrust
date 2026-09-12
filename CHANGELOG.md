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
- **Policies** match optional metadata and `forbidden_substrings`; authority
  and trust requirements are gone.

### Removed

- Source, scope, tenant, and authority models (`Source`, `Scope`,
  `TrustLevel`, `effective_authority`).
- `AuthorityCheck`, `ScopeCheck`, `TenantCheck`, and core cross-tenant /
  cross-user isolation.
- Governance as a finding category.
- Example `02_cross_tenant_read.py` (replaced by injection) and
  `07_user_ltm_vs_shared_knowledge.py` (replaced by secret redaction).
- Experimental `ZepBackend` and the `zep` extra.

### Added

- **RAG adapters**: `ChromaBackend`, `QdrantBackend`, `LlamaIndexBackend`, and
  `LangChainVectorStoreBackend`, plus extras `chroma`, `qdrant`, `llamaindex`,
  and `langchain`.
- Example `02_injection.py` and `07_secret_redaction.py`.

### Fixed

- **Mem0 platform adapter**: `MemoryClient` v2+ rejects top-level `user_id` on
  search (requires `filters` + `top_k`), returns `PENDING` with no memory id
  when `infer=True`, and flattens nested metadata on some endpoints. The
  adapter now auto-detects platform clients, stores records as-is
  (`infer=False`), keeps provenance as a JSON metadata string, and treats
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
