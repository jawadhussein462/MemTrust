# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Reports

- **HTML report redesign.** Opens with a verdict ("3 of 5 records need
  action") and a triage plan listing which records to delete, quarantine,
  and review, each record once under its strongest action. Then a severity
  breakdown, a filterable, expandable list of findings (masked excerpt,
  evidence, numbered fix steps, OWASP and CWE links, fingerprint), the
  rules that fired, and the checks and detectors that ran. Still one file
  with no network access; adds dark mode, a phone layout, and print styles.
  The footer no longer cites ASI06 for every report; each finding cites
  its own OWASP item.
- **SARIF 2.1.0** (`--sarif PATH`, `memorysec.scan.render_sarif`) for
  GitHub code scanning: one rule per finding code with help text and
  `security-severity`, one result per finding with a stable
  `partialFingerprints` entry. Snippets are omitted unless
  `include_snippets=True`.
- **Markdown summary** (`--markdown PATH`, `render_markdown`) for
  `$GITHUB_STEP_SUMMARY` and PR comments. Memory text is fenced so it
  cannot inject links or HTML.
- **`--fail-on SEVERITY`** exits `1` when a finding reaches that severity.
  Without it the exit code is unchanged (`0` on a finished scan, `2` on
  errors).
- **Findings table in the terminal**: severity, rule, record id, action,
  and OWASP item, worst first, capped at 20 rows. Memory text is never
  printed. `-q/--quiet` keeps the old counts-only output.
- **Rule catalogue** (`memorysec.rules`): title, explanation, remediation
  steps, OWASP item, and CWE (CWE-312, CWE-359, CWE-1427, CWE-345,
  CWE-1039) for every built-in finding code, shared by all formats and
  tested against the checks' `specs`.
- **JSON report** gains `schema_version` (`"1.1"`), `memorysec_version`,
  `duration_seconds`, `checks` (check → detectors), `by_rule`, and
  `by_action`. Each finding gains `check`, `title`, `remediation`, `cwe`,
  masked `evidence`, and a stable `fingerprint` (hash of rule and record
  id, never the text). Existing fields are unchanged.
- `ScanReport.action_plan()` and `ScanReport.at_or_above(severity)`.

### Changed

- **Scan-only.** MemorySec is a scanner for agent memory: poisoned facts,
  hidden instructions, and leaked secrets. The CLI is the front door
  (`memorysec scan chroma|qdrant|pgvector|pinecone|jsonl`). The HTML report
  explains the fix (review / quarantine / delete, OWASP ASI06).
- **Scan report** lists each finding with record id, type, agreeing
  detectors, a masked snippet, recommended action, and ASI06. Summary:
  total records, percentage flagged, findings by severity.
- Secret findings recommend **delete**.
- Default pipeline is security only: secrets, injection, poisoning.
- Logging uses [loguru](https://github.com/Delgan/loguru). MemorySec does not
  add or remove sinks.

### Added

- Read-only scan sources for **pgvector** and **Pinecone**, plus CLI
  scanners for Chroma, Qdrant, and JSONL. Connections never write.
  Records stream in batches; `--sample 10000` caps large stores.
- `--report report.html`, `--json findings.json`.

### Removed

- `@check`, `FunctionCheck`, `BaseCheck`, and function-style custom checks.
  `MemoryCheck` is the base class; `SecurityCheck` subclasses it.
- Correctness, end to end: contradiction, duplication, freshness,
  generalization (`memorysec.checks.correctness`), `Category.CORRECTNESS`,
  `MemoryRelationship`, `Action.SUPERSEDE`, `MemoryStatus.SUPERSEDED` /
  `EXPIRED`, expiry/validity/`supersedes` fields, core findings for
  superseded/expired/not-yet-valid records, `Config.neighbor_limit`,
  `excerpt`, and `value_change`. Scan no longer reports duplicate groups or
  stale/superseded facts.
- `protect()`, `ProtectedMemory`, `AsyncProtectedMemory`, write-time backend
  adapters (`ChromaBackend`, `Mem0Backend`, …), `--fail-on`, and the
  `memorysec check` command. The product is scan-based.
- Write and read APIs: `check_write`, `check_read`, `protect`, `revoke`,
  `Decision`, `ReadResult`, `SafeMemory`, `FilteredMemory`,
  `RevocationReport`, `Config.read_checks`, and the write/read `operations`
  split on checks. Evaluation is `MemorySec.scan`.
- Gate actions `allow`, `allow_with_warning`, and `block`, plus
  `Action.is_allowed` and `MemoryCandidate.to_record`. A scan recommends
  review, quarantine, or delete.
- In-memory and protocol backends (`InMemoryBackend`, `MemoryBackend`,
  `add` / `search` / `get` / `delete`). Scan sources are the only store
  adapters.

- **Security checks are now check + detectors.** `memorysec.checks.security`
  is organised as a father class, `SecurityCheck`, with one subclass per
  concern in its own folder (`injection/`, `poisoning/`, `secrets/`), and one
  `Detector` class per method inside each folder. A check runs its detectors,
  merges agreeing detections into a single finding
  (`evidence["detectors"]`, `evidence["scores"]`), and supports
  `min_detectors=N` voting per finding code. Each check defaults to its
  heuristic detector. The flat modules
  `checks/security/{injection,poisoning,secrets}.py` are gone;
  `InjectionCheck`, `PoisoningCheck`, `SecretsCheck` keep their import paths.
- `MemorySec(checks=[...])` **replaces** a default check when a supplied check
  has the same `name`, so `InjectionCheck(detectors=[...])` slots into the
  pipeline instead of running next to the default.
- `MemorySec.scan(..., query=...)` passes the retrieval query to checks
  (`CheckContext.query`). A concrete sequence is one batch: the other
  records are `context.existing`, for retrieval-aware detectors.
- **Simplified API**: `MemorySec().scan(...)` is the product entry point.
- **Poisoning is content-based**: `PoisoningCheck` flags false
  security-relevant facts (disabled auth, attacker hosts, approval bypasses)
  instead of gating writes on source trust / authority.
- Scan recommends **review**, **quarantine**, or **delete**. It does not
  mutate the store.

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
  and the `memorysec audit` CLI.
- Policies: `Policy`, `PolicyEngine`, `PolicyCallable`, `PolicyError`,
  `policy_matches`, `MemorySec(policies=...)`, and the `memorysec.policies`
  package. Domain rules belong in custom checks.
- Injectable clock: `Clock`, `SystemClock`, `FixedClock`, and the
  `clock=` constructor argument. Evaluation uses wall-clock UTC.
- Secret redaction: `memorysec.redaction`, `redact_secrets`, `Action.REWRITE`,
  `Decision.rewritten_content`, and example `07_secret_redaction.py`.
  Secret-bearing writes are blocked; findings report kinds only.
- Enforcement modes: `Mode`, `observe` / `warn` / `enforce`, `Config.mode`,
  `MemorySec(mode=...)`, `Decision.mode`, and `Decision.enforced`. Decisions
  always apply the recommended action.
- Semantic analyzer: `memorysec.semantic`, `SemanticAnalyzer`,
  `HeuristicSemanticAnalyzer`, `LLMSemanticAnalyzer`, `openai_completer`,
  `MemorySec(semantic_analyzer=...)`, `Config.llm_timeout`,
  `Config.semantic_fail_open`, `Config.semantic_neighbor_limit` (renamed
  `neighbor_limit`), the `openai` extra, and `SPAN_SEMANTIC_COMPARE`.
  Contradiction, supersession, and generalization checks now use local
  heuristics directly.
- Provenance model: `Provenance`, `Retrieval`, `MemoryRecord.provenance`,
  and `SafeMemory.provenance`. Lineage is `derived_from` on the record.
- Time helper module `memorysec._time` (`utcnow`, `ensure_aware`).
- Shared adapter codec `memorysec.integrations._codec` (`encode_record`,
  `decode_record`). RAG adapters store document text by id.

### Added

- **Detection methods** (all opt-in; heuristics remain the default):
  - Injection: `PromptGuardDetector` (`meta-llama/Llama-Prompt-Guard-2-86M`),
    `ProtectAIDeBERTaDetector` (`protectai/deberta-v3-base-prompt-injection-v2`),
    `DeepsetDeBERTaDetector` (`deepset/deberta-v3-base-injection`),
    `SentinelDetector` (`qualifire/prompt-injection-sentinel`),
    `PromptShieldDetector` (Azure AI Content Safety Prompt Shields),
    `LakeraGuardDetector` (Lakera Guard `/v2/guard`).
  - Poisoning: `TrustRAGDetector` (near-paraphrase cluster among retrieved neighbours,
    arXiv:2501.00879; new `poisoning_cluster` finding), `PerplexityDetector`
    (causal-LM perplexity; new `adversarial_text` finding).
  - Secrets: `EntropyDetector` (detect-secrets-style high-entropy strings),
    `DetectSecretsDetector` (Yelp detect-secrets plugins), `PiiranhaDetector`
    (`iiiorg/piiranha-v1-detect-personal-information`), `StarPIIDetector`
    (`bigcode/starpii`), `GLiNER2PIIDetector`
    (`fastino/gliner2-privacy-filter-PII-multi`), `GLiNERPIIDetector`
    (`urchade/gliner_multi_pii-v1`), `PresidioDetector` (Microsoft Presidio).
    PII detectors default to credential labels (`secret_detected`, delete);
    `*_ALL_LABELS` mappings add the new `pii_detected` finding (high, review).
  - Extras: `hf`, `gliner2`, `gliner`, `presidio`, `detect-secrets`.
  - `memorysec.text.rouge_l` and `memorysec.text.cosine`.
  - Example `09_model_detectors.py`.
- **Store audit**: `MemorySec.scan(...)` and `memorysec scan` produce a
  `ScanReport` (totals, percentage flagged, findings by severity). Each
  finding has record id, type, agreeing detectors, a masked snippet,
  recommended action, and OWASP ASI06. Example `08_scan_store.py`.
- **Detector precision and recall.** On the labelled regression corpus
  (`tests/corpus.py`) recall went from 10/17 injection, 5/11 poisoning, 6/10
  secrets to all cases, and benign false positives from 8/26 to 0/26. On a
  held-out set the patterns were not tuned on: 7/12 attacks caught (was
  1/12), 0/15 benign flagged.
  - Injection: text is deobfuscated first (invisible characters, Cyrillic
    and Greek look-alikes, diacritics, "i-g-n-o-r-e"); common
    French/Spanish/German/Portuguese/Italian variants; persona switches
    and system-prompt extraction. Ordinary preferences ("always remember to
    CC finance", "you are now connected to staging") are no longer flagged.
  - Poisoning: claims that switch off a control (auth, MFA, approval,
    security review) instead of phrase lists tuned to the README example;
    "has no authentication issues" and "requires TLS 1.2" no longer flagged.
    New `destination_redirect` finding (high, review) for payments or data
    routed to a new destination ("send all invoices to x@y.io instead").
  - Secrets: stated credentials ("my password is hunter2", "the PIN is
    4821"), Stripe and Anthropic keys, connection strings with passwords.
- **Scan-time security checks.** Secrets, injection, and poisoning run on
  every stored record, including content that entered the store outside
  MemorySec. Custom checks run during the same scan.
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
  shared `memorysec.integrations._codec`; unreadable state fails closed as
  `QUARANTINED`.
- **Status changes duplicated records.** Every shipped adapter now implements
  `set_status` in place (Chroma `update`, Qdrant `set_payload`, Mem0
  `update(metadata=...)`, LangGraph `put`, LlamaIndex/LangChain replace by
  id). The generic fallback deletes the stale copy when a backend assigns a
  new id instead of upserting.
- **Qdrant adapter crashed against the real client** (plain-dict points,
  non-UUID ids). It now sends `PointStruct`s and maps MemorySec ids to stable
  UUIDv5 point ids. Keyword-only mode ranks by similarity instead of
  substring match, so write-time neighbour lookup finds related facts.
- **LlamaIndex adapter** returned node UUIDs instead of MemorySec ids, so
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

[Unreleased]: https://github.com/memorysec/memorysec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/memorysec/memorysec/releases/tag/v0.1.0
