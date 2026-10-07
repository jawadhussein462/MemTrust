# Contributing to MemorySec

Thanks for your interest in improving MemorySec. This project aims to be a
familiar, well-typed, batteries-included toolkit — contributions should preserve
that feel.

## Development setup

MemorySec requires Python 3.11+. We recommend [uv](https://docs.astral.sh/uv/).

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
pre-commit install
```

## The toolchain

```bash
ruff check memorysec tests examples      # lint
ruff format memorysec tests examples     # format
mypy memorysec                           # type-check
pytest                                  # tests
```

All four must pass. CI runs them on Python 3.11–3.13.

## Design principles

- **CLI is the front door.** Most users run `memorysec scan`.
- **Find, then fix.** Scan finds poisoned facts, hidden instructions, and
  leaked secrets. The HTML report explains the recommended action.
- **Deterministic first.** Checks are cheap, offline, and fully functional
  with zero external services.
- **Extension via Protocols, not inheritance.** New checks and scan sources
  should satisfy the relevant `typing.Protocol`.
- **Never log or store secrets.** Findings, reports, and telemetry must not
  include secret values. Scan snippets are masked.
- **Scan connections are read-only.** Scan sources list and fetch; they never
  upsert or delete.
- **Sync is always sync; async is always async.** No method returns a coroutine
  conditionally.

## Adding a detector (a new method for an existing security concern)

Security checks are organised as one folder per concern, one module per
method: `memorysec/checks/security/{injection,poisoning,secrets}/<method>.py`.

1. Subclass `BaseDetector` (or `HFTextClassifierDetector` /
   `HFTokenClassifierDetector` from `security/_hf.py` for Hugging Face
   models) and set a unique `name`.
2. Implement `detect_text(text)` — or `detect(candidate, context)` if you need
   the query or neighbouring records — and return `Detection`s via
   `self.hit(...)`. Use `code=` to pick one of the parent check's `specs`.
3. **Never** put matched text or secret values in evidence: kinds, labels,
   counts, and scores only.
4. Import optional dependencies lazily inside `_load()`, raise
   `ConfigurationError` with the install hint, and accept an injectable
   inference callable (`classify=`, `tag=`, `transport=`, ...) so the detector
   is testable offline. Add an extra to `pyproject.toml` and a mypy override.
5. Export it from the folder's `__init__.py`, add a row to the README table,
   and add fake-driven tests under `tests/unit/`.

## Adding a check

1. Subclass `SecurityCheck` in a new
   `memorysec/checks/security/<concern>/` folder with `name`, `default_code`,
   `specs` (code -> `FindingSpec`), `default_detectors()`, and at least a
   heuristic detector.
2. Return a list of `Finding`s; set `recommended_action` to `review`,
   `quarantine`, or `delete`.
3. Add it to `default_checks()` only if it should run by default (defaults
   must stay offline and dependency-free).
4. Add unit tests under `tests/unit/` and, if security-relevant, an invariant
   test under `tests/security/`.

## Adding a scan source

1. Implement `records(batch_size=..., sample=...)` as a read-only iterator.
2. Stream in batches. Honour `--sample`. Never write.
3. Import the provider SDK lazily; add an optional extra in `pyproject.toml`.
4. Wire it into `memorysec scan <name>` in `memorysec/cli.py`.
5. Test against an in-process fake.

## Commit / PR expectations

- Keep the public API small and documented (docstrings on public APIs).
- Update `CHANGELOG.md` under `[Unreleased]`.
- Security-relevant changes must include tests that would fail without the fix.

## Reporting security issues

Please see [SECURITY.md](SECURITY.md) — do not open public issues for
vulnerabilities.
