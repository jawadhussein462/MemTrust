# Contributing to MemTrust

Thanks for your interest in improving MemTrust. This project aims to be a
familiar, well-typed, batteries-included SDK — contributions should preserve
that feel.

## Development setup

MemTrust requires Python 3.11+. We recommend [uv](https://docs.astral.sh/uv/).

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
pre-commit install
```

## The toolchain

```bash
ruff check memtrust tests examples      # lint
ruff format memtrust tests examples     # format
mypy memtrust                           # type-check
pytest                                  # tests
```

All four must pass. CI runs them on Python 3.11–3.13.

## Design principles

- **Simple API on top, rigorous trust model underneath.** Most users should
  only import from the top-level `memtrust` package.
- **Deterministic first.** Cheap, offline checks run before any semantic/LLM
  analysis. The library must be fully functional with zero external services.
- **Extension via Protocols, not inheritance.** New checks, analyzers, audit
  stores, and backends should satisfy the relevant `typing.Protocol`.
- **Core enforcement stays in the engine.** Tenant/user isolation and
  revoked/expired filtering must not be relocatable into optional checks
  (security Invariant 7).
- **Never log or store secrets.** Redact before findings, audit, and telemetry.
- **Sync is always sync; async is always async.** No method returns a coroutine
  conditionally.

## Adding a check

1. Implement a class with `name: str` and `check(candidate, context)` in
   `memtrust/checks/` (subclass `BaseCheck` for convenience).
2. Return a list of `Finding`s; set `recommended_action` where appropriate.
3. Add it to `default_checks()` only if it should run by default.
4. Add unit tests under `tests/unit/` and, if security-relevant, an invariant
   test under `tests/security/`.

## Adding a backend adapter

1. Implement `add`/`search`/`get`/`delete` (and async variants if relevant).
2. Import the provider SDK lazily; add an optional extra in `pyproject.toml`.
3. Store the full record in provider metadata and reconstruct it on read so
   provenance/scope survive the round-trip.
4. Add it to the adapter conformance tests using a fake client.

## Commit / PR expectations

- Keep the public API small and documented (docstrings on public APIs).
- Update `CHANGELOG.md` under `[Unreleased]`.
- Security-relevant changes must include tests that would fail without the fix.

## Reporting security issues

Please see [SECURITY.md](SECURITY.md) — do not open public issues for
vulnerabilities.
