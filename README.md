# MemorySec

Scan your AI agent's memory for poisoned facts, hidden instructions and leaked secrets, locally, in minutes.

The scan finds problems. The report explains the fix.

```bash
pip install memorysec
```

```bash
memorysec scan qdrant \
    --url http://localhost:6333 \
    --collection agent_memory \
    --report report.html
```

```text
✓ Scanned 48,291 records
! 137 records flagged (0.28%)
  • 12 critical  • 31 high  • 58 medium  • 36 low

✓ Report written to report.html
```

The command prints that summary. Marks are colored in a terminal. The HTML file is what you forward. A Qdrant scan needs `pip install "memorysec[qdrant]"`; other stores need their own extra, listed below.

MemorySec does not own your memory store. Connections are **read-only**, records stream in batches, and `--sample 10000` caps very large stores.

---

## Find

Point the CLI at the store your agent already uses. Nothing is modified.

```bash
pip install "memorysec[chroma]"     # Chroma
pip install "memorysec[qdrant]"     # Qdrant
pip install "memorysec[pgvector]"   # Postgres / pgvector
pip install "memorysec[pinecone]"   # Pinecone
```

```bash
memorysec scan chroma --path ./chroma_db --collection agent_memory --report report.html
memorysec scan qdrant --url http://localhost:6333 --collection agent_memory --sample 10000
memorysec scan pgvector --dsn postgresql://localhost/app --table memories --text-column content --id-column id
memorysec scan pinecone --index agent-memory --namespace prod --text-field content
memorysec scan jsonl export.jsonl --report report.html --json findings.json
```

`--sample N` stops after N records.

The same scan is available from Python:

```python
from memorysec import MemorySec
from memorysec.scan import ChromaScanSource

report = MemorySec().scan(ChromaScanSource(path="./chroma_db", collection="agent_memory"))
print(report)
```

`print(report)` prints the same summary as the CLI.

---

## Fix

`--report report.html` writes **one HTML file** you can forward: total records, percentage flagged, and findings by severity. Each finding shows:

- the record ID and finding type
- which detectors agreed
- a masked snippet (secrets are never in the file)
- the recommended action — **review**, **quarantine**, or **delete**
- the [OWASP ASI06](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/) Memory & Context Poisoning reference

`--json findings.json` is the same data for ticketing and CI.

---

## What it looks for

Three security checks. That is the product.

- **Poisoned facts** — false or attacker-controlled claims planted into long-term memory (OWASP ASI06).
- **Hidden instructions** — persistent prompt injection that should never be stored.
- **Leaked secrets** — keys, tokens, passwords, connection strings.

No cloud account. No LLM API key. Deterministic heuristics are the default and run fully offline. Model and hosted detectors are opt-in and stack:

```python
from memorysec import MemorySec
from memorysec.checks.security import InjectionCheck, PoisoningCheck, SecretsCheck
from memorysec.checks.security.injection import HeuristicInjectionDetector, PromptGuardDetector
from memorysec.checks.security.poisoning import HeuristicPoisoningDetector, TrustRAGDetector
from memorysec.checks.security.secrets import HeuristicSecretsDetector, EntropyDetector, PiiranhaDetector

guard = MemorySec(checks=[
    InjectionCheck(detectors=[HeuristicInjectionDetector(), PromptGuardDetector()]),
    PoisoningCheck(detectors=[HeuristicPoisoningDetector(), TrustRAGDetector()]),
    SecretsCheck(detectors=[HeuristicSecretsDetector(), EntropyDetector(), PiiranhaDetector()]),
])
```

A configured check replaces the default of the same name. Detectors that agree are merged into one finding (`evidence["detectors"]`, `evidence["scores"]`); `min_detectors=2` requires two methods to agree.

| Concern | Detector | Method | Install |
|---|---|---|---|
| **Injection** | `HeuristicInjectionDetector` | deobfuscation + phrase patterns (default) | — |
| | `PromptGuardDetector` | `meta-llama/Llama-Prompt-Guard-2-86M` (or `-22M`) | `memorysec[hf]` |
| | `ProtectAIDeBERTaDetector` | `protectai/deberta-v3-base-prompt-injection-v2` | `memorysec[hf]` |
| | `DeepsetDeBERTaDetector` | `deepset/deberta-v3-base-injection` | `memorysec[hf]` |
| | `SentinelDetector` | `qualifire/prompt-injection-sentinel` (ModernBERT) | `memorysec[hf]` |
| | `PromptShieldDetector` | Azure AI Content Safety Prompt Shields (document attack) | API key |
| | `LakeraGuardDetector` | Lakera Guard `/v2/guard` | API key |
| **Poisoning** | `HeuristicPoisoningDetector` | control-bypass + redirect patterns (default) | — |
| | `TrustRAGDetector` | tight near-paraphrase cluster among retrieved neighbours ([TrustRAG](https://arxiv.org/abs/2501.00879)) | — (optional `embed`) |
| | `PerplexityDetector` | causal-LM perplexity for adversarial suffixes | `memorysec[hf]` |
| **Secrets** | `HeuristicSecretsDetector` | key formats + stated credentials (default) | — |
| | `EntropyDetector` | high-entropy strings (detect-secrets approach) | — |
| | `DetectSecretsDetector` | Yelp detect-secrets provider plugins | `memorysec[detect-secrets]` |
| | `PiiranhaDetector` | `iiiorg/piiranha-v1-detect-personal-information` | `memorysec[hf]` |
| | `StarPIIDetector` | `bigcode/starpii` (secrets in code) | `memorysec[hf]` |
| | `GLiNER2PIIDetector` | `fastino/gliner2-privacy-filter-PII-multi` | `memorysec[gliner2]` |
| | `GLiNERPIIDetector` | `urchade/gliner_multi_pii-v1` | `memorysec[gliner]` |
| | `PresidioDetector` | Microsoft Presidio `AnalyzerEngine` | `memorysec[presidio]` |

---

## Integrations

```bash
pip install "memorysec[chroma]"     # `memorysec scan chroma`
pip install "memorysec[qdrant]"     # `memorysec scan qdrant`
pip install "memorysec[pgvector]"   # `memorysec scan pgvector`
pip install "memorysec[pinecone]"   # `memorysec scan pinecone`
pip install "memorysec[otel]"       # OpenTelemetry tracing
```

Scan sources only **read**.

---

## Architecture

```text
      memorysec scan  chroma · qdrant · pgvector · pinecone · jsonl
                           │
                 Injection · Poisoning · Secrets
                           │
              HTML report  review / quarantine / delete
                           │
              Long-term memory / RAG (read-only)
```

```text
memorysec/checks/security/
  base.py               SecurityCheck, Detector, Detection, FindingSpec
  injection/            InjectionCheck + heuristic, prompt_guard, ...
  poisoning/            PoisoningCheck + heuristic, trustrag, perplexity
  secrets/              SecretsCheck + heuristic, entropy, piiranha, ...
memorysec/scan/
  chroma.py qdrant.py pgvector.py pinecone.py jsonl.py
  html.py               one-file report
```

---

## Observability

MemorySec logs with [loguru](https://github.com/Delgan/loguru) and does not add or remove sinks.
OpenTelemetry tracing is optional and injected:

```python
from memorysec import MemorySec
from memorysec.telemetry.otel import otel_tracer

guard = MemorySec(tracer=otel_tracer())
```

Raw memory content and secrets are never placed on spans by default.

---

## Status & limitations

MemorySec is **v0.1 (alpha)**. The default security detectors are **heuristic and not complete** — see [SECURITY.md](SECURITY.md). Treat them as strong signals in a defense-in-depth strategy, not a guarantee, and stack model detectors where recall matters.

`tests/corpus.py` is a labelled regression set (injection, poisoning, secrets, and benign memories that must stay allowed). It was written alongside the heuristic detectors, so it is not a benchmark. On a separate held-out set the patterns were not tuned on, they caught 7 of 12 attacks and flagged 0 of 15 benign memories; the misses (paraphrases, encodings, most non-English text) are kept in `KNOWN_MISSES` — they are what the model-based detectors above are for.

## License

[Apache-2.0](LICENSE)
