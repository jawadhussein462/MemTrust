"""Runtime configuration for a MemTrust instance.

Configuration is passed by dependency injection (constructor argument), never
read from module-level globals. Every field has a safe default so that
``MemTrust()`` works out of the box.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .models.enums import Mode


class Config(BaseModel):
    """Tunable behaviour for checks, policies, and enforcement."""

    model_config = ConfigDict(extra="forbid")

    mode: Mode = Field(default=Mode.ENFORCE)
    fail_closed: bool = Field(
        default=True,
        description="On internal check errors, treat as a blocking violation rather than allowing.",
    )

    # Correctness tuning
    duplicate_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    contradiction_enabled: bool = Field(default=True)
    semantic_neighbor_limit: int = Field(
        default=20, ge=0, description="Max existing records fetched to compare a candidate against."
    )

    # Security tuning
    redact_secrets: bool = Field(default=True)

    # Protected-backend behaviour
    store_quarantined: bool = Field(
        default=True,
        description="Persist quarantined writes with QUARANTINED status instead of dropping.",
    )
    raise_on_blocked_add: bool = Field(
        default=False, description="If True, protected .add raises when a write is blocked."
    )

    # Semantic / LLM
    llm_timeout: float = Field(default=10.0, gt=0.0)
    semantic_fail_open: bool = Field(
        default=True,
        description="If a semantic analyzer errors/times out, skip its findings vs. block.",
    )

    # Audit
    audit_content: bool = Field(
        default=True, description="Store a redacted, truncated content preview in audit events."
    )
    audit_content_max_len: int = Field(default=500, ge=0)


__all__ = ["Config"]
