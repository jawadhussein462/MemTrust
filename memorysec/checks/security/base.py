"""Security check framework: one check per concern, one detector per method.

The hierarchy is::

    BaseCheck
    └── SecurityCheck                  (this module; the "father" class)
        ├── InjectionCheck             (security/injection/)
        ├── PoisoningCheck             (security/poisoning/)
        └── SecretsCheck               (security/secrets/)

Each :class:`SecurityCheck` owns a list of :class:`Detector` objects. A
detector implements *one method* of finding the concern -- a regex heuristic,
a Hugging Face classifier, a hosted API, a statistical filter -- and returns
:class:`Detection` objects. The check turns detections into
:class:`~memorysec.Finding` objects using a per-code table of severity, action,
and message, merging evidence when several detectors agree.

Detectors never see the decision: they report, the check maps, the engine
aggregates. Adding a method means adding a detector class; adding a concern
means adding a ``SecurityCheck`` subclass with its ``specs`` table.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

from ...context import CheckContext
from ...exceptions import ConfigurationError
from ...models.enums import Action, Category, Severity
from ...models.finding import Finding
from ...models.memory import MemoryCandidate
from ...telemetry import get_logger
from ..base import BaseCheck

_logger = get_logger(__name__)


@dataclass(frozen=True)
class Detection:
    """What one detector noticed about a candidate.

    ``code`` selects the finding the parent check emits (``None`` means the
    check's default code). ``score`` is the detector's confidence when it has
    one (model probability, statistical density). ``evidence`` must never
    contain raw secrets or the full text; kinds, counts, and scores only.
    """

    detector: str
    code: str | None = None
    score: float | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    """One method of detecting a security concern."""

    name: str

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]: ...


class BaseDetector:
    """Convenience base: implement :meth:`detect_text` for content-only methods.

    Detectors that need the retrieval query or the neighbouring records
    (``context.query``, ``context.existing``) override :meth:`detect` instead.
    """

    name: str = "base"

    def detect(self, candidate: MemoryCandidate, context: CheckContext) -> list[Detection]:
        return self.detect_text(candidate.content)

    def detect_text(self, text: str) -> list[Detection]:
        raise NotImplementedError

    def hit(
        self,
        *,
        code: str | None = None,
        score: float | None = None,
        **evidence: object,
    ) -> Detection:
        """Build a :class:`Detection` attributed to this detector."""
        return Detection(detector=self.name, code=code, score=score, evidence=evidence)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"


@dataclass(frozen=True)
class FindingSpec:
    """Severity, action, and message the check attaches to a finding code."""

    severity: Severity
    action: Action
    message: str


class SecurityCheck(BaseCheck):
    """Base class for security checks: runs detectors and maps them to findings.

    Subclasses declare ``name``, ``default_code``, ``specs`` (code -> spec),
    and :meth:`default_detectors`. Security checks run during a scan, so
    content that entered the store through another pipeline is still screened.

    ``min_detectors`` is a vote threshold counted per finding code: with
    ``min_detectors=2`` a code is reported only when two distinct detectors
    raised it, which trades recall for precision when stacking noisy methods.
    """

    category: ClassVar[Category] = Category.SECURITY
    default_code: ClassVar[str] = ""
    specs: ClassVar[Mapping[str, FindingSpec]] = {}

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        *,
        min_detectors: int = 1,
    ) -> None:
        resolved = list(detectors) if detectors is not None else self.default_detectors()
        if not resolved:
            raise ConfigurationError(f"Check {self.name!r} needs at least one detector.")
        names = [d.name for d in resolved]
        if len(set(names)) != len(names):
            raise ConfigurationError(
                f"Check {self.name!r}: detector names must be unique {names!r}."
            )
        if min_detectors < 1:
            raise ConfigurationError("min_detectors must be >= 1.")
        if min_detectors > len(resolved):
            raise ConfigurationError(
                f"min_detectors={min_detectors} exceeds the {len(resolved)} configured detector(s)."
            )
        self.detectors: list[Detector] = resolved
        self.min_detectors = min_detectors

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        """Detectors used when none are given (deterministic and offline)."""
        raise NotImplementedError

    # -- pipeline ----------------------------------------------------------------

    def check(self, candidate: MemoryCandidate, context: CheckContext) -> list[Finding]:
        by_code: dict[str, list[Detection]] = {}
        first_error: Exception | None = None
        for detector in self.detectors:
            try:
                detections = detector.detect(candidate, context)
            except Exception as exc:
                _logger.warning(
                    "detector {!r} in check {!r} raised {}",
                    detector.name,
                    self.name,
                    type(exc).__name__,
                )
                first_error = first_error or exc
                continue
            for detection in detections:
                code = detection.code or self.default_code
                if code not in self.specs:
                    raise ConfigurationError(
                        f"Detector {detector.name!r} emitted unknown code {code!r} for check "
                        f"{self.name!r}; known codes: {sorted(self.specs)}."
                    )
                by_code.setdefault(code, []).append(detection)

        # A failing detector must not silently weaken the check: under
        # fail-closed the engine turns this into a blocking ``check_error``.
        if first_error is not None and context.config.fail_closed:
            raise first_error

        findings: list[Finding] = []
        for code, detections in by_code.items():
            voters = {d.detector for d in detections}
            if len(voters) < self.min_detectors:
                continue
            findings.append(self.finding(code, detections))
        return findings

    def finding(self, code: str, detections: Sequence[Detection]) -> Finding:
        """Turn the detections that share ``code`` into a single finding."""
        spec = self.specs[code]
        return Finding(
            code=code,
            category=self.category,
            severity=spec.severity,
            message=spec.message,
            evidence=merge_evidence(detections),
            check=self.name,
            recommended_action=spec.action,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(detectors={self.detectors!r})"


def merge_evidence(detections: Sequence[Detection]) -> dict[str, object]:
    """Combine detector evidence: list values are unioned, scalars keep the first."""
    evidence: dict[str, object] = {"detectors": sorted({d.detector for d in detections})}
    scores = {d.detector: round(d.score, 4) for d in detections if d.score is not None}
    if scores:
        evidence["scores"] = scores
    for detection in detections:
        for key, value in detection.evidence.items():
            if key in ("detectors", "scores"):
                continue
            current = evidence.get(key)
            if current is None:
                evidence[key] = list(value) if isinstance(value, list | tuple | set) else value
            elif isinstance(current, list) and isinstance(value, list | tuple | set):
                merged = [*current, *(v for v in value if v not in current)]
                try:
                    evidence[key] = sorted(merged)
                except TypeError:
                    evidence[key] = merged
    return evidence


__all__ = [
    "BaseDetector",
    "Detection",
    "Detector",
    "FindingSpec",
    "SecurityCheck",
    "merge_evidence",
]
