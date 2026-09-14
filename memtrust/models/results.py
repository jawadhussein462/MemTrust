"""Structured return values for reads, writes, and revocation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from .decision import Decision
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


__all__ = [
    "AddResult",
    "FilteredMemory",
    "ReadResult",
    "RevocationReport",
    "SafeMemory",
]
