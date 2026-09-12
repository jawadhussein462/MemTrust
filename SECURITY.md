# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue. Email the maintainers (see repository metadata) with a description, steps
to reproduce, and impact. We aim to acknowledge reports promptly and to
coordinate disclosure.

Do **not** include real secrets, credentials, or production customer data in
reports.

## Scope and threat model

MemTrust is a **trust boundary** between an AI agent and a long-term
knowledge memory (RAG store, user memory, retrieved documents). It is
designed to reduce the risk that persistent memory becomes poisoned, injected,
secret-bearing, contradictory, stale, or duplicated. It is one layer in a
defense-in-depth strategy — not a complete security solution.

The product is oriented around two families of checks:

- **Security** — poisoning, injection, secrets.
- **Correctness** — contradictions, duplicates, freshness.

### What MemTrust enforces reliably (deterministic)

- **Filtering** of revoked, expired, quarantined, and superseded memories on
  read (core engine, non-bypassable by customizing the check list).
- **Secret redaction** before content reaches findings, audit, or telemetry.
- **Mode semantics**: `observe` never alters backend behavior; `enforce` blocks
  critical violations by default.

These are covered by explicit invariant tests.

## Important limitations — please read

The following detectors are **heuristic** and are **not complete or
production-perfect**. They produce strong *signals*, not guarantees.

- **Poisoning detection** is pattern-based. It looks for false
  security-relevant facts (disabled auth, attacker hosts, approval bypasses).
  It will miss novel phrasings, obfuscation, encodings, and non-English text.
- **Injection / persistent-instruction detection** is pattern-based. It will
  miss novel phrasings, obfuscation, encodings, and non-English text, and can
  produce false positives.
- **Secret detection** matches common, high-signal credential formats (API
  keys, tokens, private keys, credential assignments). It will miss custom or
  unusual secret formats. Do not rely on it as your only secret scanner.
- **Duplicate / contradiction / supersession** use normalization, token
  overlap, negation/polarity, and time — not deep understanding. The optional
  LLM analyzer improves quality but adds latency, cost, and its own failure
  modes (mitigated by timeouts and configurable fail-open/closed behavior).
- **Generalization detection** is an extension point with a basic heuristic
  implementation.

## Operational guidance

- Start in `mode="observe"`, review the audit trail, then move to `enforce`.
- Keep `fail_closed=True` (default) in production so internal check errors block
  rather than silently allow.
- Configure a persistent `AuditStore` (e.g. `JSONLAuditStore`) so revocation
  has history to work with.
- Add domain-specific custom checks and policies; the built-ins are a baseline.
- The LLM analyzer never receives content until after secret redaction; keep it
  that way in any custom analyzer.

## Supported versions

During the 0.x series, only the latest released version receives security fixes.
