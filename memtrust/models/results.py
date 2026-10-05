"""Structured return values for reads, writes, and revocation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from .enums import Action, Severity
from .finding import Finding
from .memory import MemoryRecord


@dataclass(frozen=True)
class SafeMemory:
    """A memory that passed read-time enforcement, wrapped for easy access.

    Exposes the fields an agent typically wants without digging into the
    record::

        for item in results:
            print(item.memory)
    """

    record: MemoryRecord
    score: float | None = None

    @property
    def id(self) -> str:
        return self.record.id

    @property
    def memory(self) -> str:
        return self.record.content

    @property
    def content(self) -> str:
        return self.record.content


@dataclass(frozen=True)
class FilteredMemory:
    """A memory that was withheld at read time, with the reason why."""

    record: MemoryRecord
    finding: Finding

    @property
    def reason(self) -> str:
        return self.finding.message

    @property
    def code(self) -> str:
        return self.finding.code


@dataclass
class ReadResult:
    """Outcome of a read check: safe results plus what was filtered and why.

    Iterating a ``ReadResult`` yields the *safe* memories, so it can be used
    directly in a ``for`` loop, while ``.filtered`` explains withheld items.
    """

    results: list[SafeMemory] = field(default_factory=list)
    filtered: list[FilteredMemory] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def safe(self) -> list[SafeMemory]:
        return self.results

    def __iter__(self) -> Iterator[SafeMemory]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(self, index: int) -> SafeMemory:
        return self.results[index]


class RevocationReport(BaseModel):
    """Impact report produced by :meth:`MemTrust.revoke`.

    Serializable to JSON. Lists the memory that was revoked plus anything
    derived from it.
    """

    model_config = ConfigDict(extra="forbid")

    memory_id: str
    revoked_memories: list[str] = Field(default_factory=list)
    directly_revoked: list[str] = Field(default_factory=list)
    transitively_revoked: list[str] = Field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.revoked_memories)


class ScanFinding(BaseModel):
    """One problem in a stored record, safe to forward.

    Snippets are secret-masked. Raw content is never included.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    severity: Severity
    detectors: list[str] = Field(default_factory=list)
    snippet: str = ""
    action: Action
    owasp: str = "ASI06: Memory & Context Poisoning"
    message: str = ""


class ScanReport(BaseModel):
    """Audit of a memory store produced by :meth:`MemTrust.scan`.

    Counts every record examined and lists security findings (poisoned
    facts, hidden instructions, leaked secrets) with a recommended action.
    """

    model_config = ConfigDict(extra="ignore")

    total: int = 0
    findings: list[ScanFinding] = Field(default_factory=list)
    source: str = ""
    sample: int | None = None
    generated_at: datetime | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flagged(self) -> int:
        return len({item.id for item in self.findings})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flagged_pct(self) -> float:
        if not self.total:
            return 0.0
        return round(100.0 * self.flagged / self.total, 1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            key = item.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def clean(self) -> bool:
        return not self.findings

    def worst_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((item.severity for item in self.findings), key=lambda s: s.rank)

    def __str__(self) -> str:
        pct = f"{self.flagged_pct:g}%"
        lines = [f"Scanned {_count(self.total, 'record')}: {self.flagged} flagged ({pct})."]
        if self.by_severity:
            parts = ", ".join(
                f"{count} {name}"
                for name, count in sorted(
                    self.by_severity.items(),
                    key=lambda kv: Severity(kv[0]).rank,
                    reverse=True,
                )
            )
            lines.append(f"By severity: {parts}.")
        if self.findings:
            lines.append("")
            for item in self.findings:
                detectors = ", ".join(item.detectors) if item.detectors else "—"
                lines.append(
                    f"  {item.id}  {item.type}  {item.severity.value}  "
                    f"{item.action.value}  [{detectors}]"
                )
        if self.clean:
            lines.append("No poisoned facts, hidden instructions, or leaked secrets found.")
        return "\n".join(lines)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


__all__ = [
    "FilteredMemory",
    "ReadResult",
    "RevocationReport",
    "SafeMemory",
    "ScanFinding",
    "ScanReport",
]
