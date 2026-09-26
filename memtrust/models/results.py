"""Structured return values for reads, writes, and revocation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from .decision import Decision
from .enums import Action, MemoryStatus
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


@dataclass
class AddResult:
    """Outcome of a protected write."""

    allowed: bool
    decision: Decision
    record: MemoryRecord | None = None

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def id(self) -> str | None:
        return self.record.id if self.record is not None else None


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
    """A stored record that read enforcement would withhold, and why.

    Carries ids and finding codes only — never content — so a report can be
    shared without leaking the secrets it found.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    codes: list[str]
    action: Action


class ScanReport(BaseModel):
    """Audit of a memory store produced by :meth:`MemTrust.scan`.

    ``flagged`` lists records still marked active that the checks would now
    withhold (latent poisoning, injections, secrets). Records already
    quarantined, superseded, revoked, or expired are counted in ``by_status``
    but are not problems: read enforcement withholds them by design.
    """

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    served: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_code: dict[str, int] = Field(default_factory=dict)
    flagged: list[ScanFinding] = Field(default_factory=list)
    duplicate_groups: list[list[str]] = Field(
        default_factory=list, description="Ids of served records with identical normalized text."
    )

    @property
    def clean(self) -> bool:
        return not self.flagged and not self.duplicate_groups

    def __str__(self) -> str:
        lines = [f"Scanned {_count(self.total, 'record')}: {self.served} served to agents."]
        lifecycle = {k: v for k, v in sorted(self.by_status.items()) if k != MemoryStatus.ACTIVE}
        if lifecycle:
            parts = ", ".join(f"{k} {v}" for k, v in lifecycle.items())
            lines.append(f"Withheld by lifecycle: {parts}.")
        if self.flagged:
            lines.append("")
            lines.append(f"{_count(len(self.flagged), 'active record')} would be withheld:")
            for item in self.flagged:
                lines.append(f"  {item.id}  {', '.join(item.codes)}  -> {item.action.value}")
        if self.duplicate_groups:
            dupes = sum(len(g) for g in self.duplicate_groups)
            lines.append("")
            groups = _count(len(self.duplicate_groups), "duplicate group")
            lines.append(f"{groups} ({_count(dupes, 'record')}):")
            for group in self.duplicate_groups:
                lines.append(f"  {', '.join(group)}")
        if self.clean:
            lines.append("No problems found.")
        return "\n".join(lines)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


__all__ = [
    "AddResult",
    "FilteredMemory",
    "ReadResult",
    "RevocationReport",
    "SafeMemory",
    "ScanFinding",
    "ScanReport",
]
