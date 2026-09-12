"""The :class:`Source` of a memory: where it came from and how trusted it is."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import TrustLevel

# Default authority (permission-to-assert) implied by a source's trust level.
# Authority is intentionally low even for fairly trusted sources: being a
# trusted *source* is not the same as having authority to define policy.
_DEFAULT_AUTHORITY: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 0.05,
    TrustLevel.USER: 0.30,
    TrustLevel.AGENT: 0.40,
    TrustLevel.INTERNAL: 0.70,
    TrustLevel.TRUSTED: 0.85,
    TrustLevel.AUTHORITATIVE: 1.00,
}


def default_authority_for(trust: TrustLevel) -> float:
    """Return the default authority score implied by a trust level."""
    return _DEFAULT_AUTHORITY[trust]


class Source(BaseModel):
    """Provenance of a candidate memory.

    Example::

        Source(type="customer_ticket", id="ticket_123", trust="untrusted")
    """

    model_config = ConfigDict(extra="forbid", frozen=False)

    type: str = Field(description="Kind of source, e.g. 'customer_ticket', 'conversation'.")
    id: str | None = Field(default=None, description="Stable identifier of the source document.")
    trust: TrustLevel = Field(
        default=TrustLevel.UNTRUSTED,
        description="How trusted the source is. Defaults to the safest assumption.",
    )
    uri: str | None = Field(default=None, description="Optional locator for the source.")
    excerpt: str | None = Field(
        default=None,
        description="Optional raw text the memory was derived from (used by generalization checks).",
    )
    metadata: dict[str, object] = Field(default_factory=dict)

    @property
    def default_authority(self) -> float:
        """The authority score implied by this source's trust level."""
        return default_authority_for(self.trust)


__all__ = ["Source", "default_authority_for"]
