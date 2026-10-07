"""Secrets: credentials, keys, tokens, and (opt-in) personal data.

:class:`SecretsCheck` runs one or more detectors:

=========================  ================================================  ================
Detector                   Method                                            Needs
=========================  ================================================  ================
HeuristicSecretsDetector   known key formats + stated credentials (default)  nothing
EntropyDetector            high-entropy strings (detect-secrets approach)    nothing
DetectSecretsDetector      Yelp detect-secrets provider plugins              [detect-secrets]
PiiranhaDetector           iiiorg/piiranha-v1-detect-personal-information    [hf]
StarPIIDetector            bigcode/starpii (PII/secrets in code)             [hf]
GLiNER2PIIDetector         fastino/gliner2-privacy-filter-PII-multi          [gliner2]
GLiNERPIIDetector          urchade/gliner_multi_pii-v1                       [gliner]
PresidioDetector           Microsoft Presidio AnalyzerEngine                 [presidio]
=========================  ================================================  ================

Detectors backed by PII models default to credential-like labels only
(``secret_detected``, delete). Each exposes ``*_ALL_LABELS`` to also report
personal data as ``pii_detected`` (review).
"""

from __future__ import annotations

from .check import SecretsCheck
from .detect_secrets import DetectSecretsDetector
from .entropy import EntropyDetector, shannon_entropy
from .gliner2_pii import (
    GLINER2_ALL_LABELS,
    GLINER2_PII_LABELS,
    GLINER2_SECRET_LABELS,
    GLiNER2PIIDetector,
)
from .gliner_pii import (
    GLINER_ALL_LABELS,
    GLINER_PII_LABELS,
    GLINER_SECRET_LABELS,
    GLiNERPIIDetector,
)
from .heuristic import HeuristicSecretsDetector, secret_kinds
from .piiranha import (
    PIIRANHA_ALL_LABELS,
    PIIRANHA_PII_LABELS,
    PIIRANHA_SECRET_LABELS,
    PiiranhaDetector,
)
from .presidio import (
    PRESIDIO_ALL_LABELS,
    PRESIDIO_PII_LABELS,
    PRESIDIO_SECRET_LABELS,
    PresidioDetector,
)
from .starpii import STARPII_ALL_LABELS, STARPII_PII_LABELS, STARPII_SECRET_LABELS, StarPIIDetector

__all__ = [
    "GLINER2_ALL_LABELS",
    "GLINER2_PII_LABELS",
    "GLINER2_SECRET_LABELS",
    "GLINER_ALL_LABELS",
    "GLINER_PII_LABELS",
    "GLINER_SECRET_LABELS",
    "PIIRANHA_ALL_LABELS",
    "PIIRANHA_PII_LABELS",
    "PIIRANHA_SECRET_LABELS",
    "PRESIDIO_ALL_LABELS",
    "PRESIDIO_PII_LABELS",
    "PRESIDIO_SECRET_LABELS",
    "STARPII_ALL_LABELS",
    "STARPII_PII_LABELS",
    "STARPII_SECRET_LABELS",
    "DetectSecretsDetector",
    "EntropyDetector",
    "GLiNER2PIIDetector",
    "GLiNERPIIDetector",
    "HeuristicSecretsDetector",
    "PiiranhaDetector",
    "PresidioDetector",
    "SecretsCheck",
    "StarPIIDetector",
    "secret_kinds",
    "shannon_entropy",
]
