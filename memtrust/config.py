"""Runtime configuration for a MemTrust instance.

Configuration is passed by dependency injection (constructor argument), never
read from module-level globals. Every field has a safe default so that
``MemTrust()`` works out of the box.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .models.enums import Mode, TrustLevel


def _default_required_authority() -> dict[str, float]:
    # Namespaces that hold rules/policy require high authority to write.
    return {
        "company_policy": 0.9,
        "finance_policy": 0.9,
        "policy": 0.9,
        "policies": 0.9,
        "security_policy": 0.9,
        "compliance": 0.9,
    }


class Config(BaseModel):
    """Tunable behaviour for checks, policies, and enforcement."""

    model_config = ConfigDict(extra="forbid")

    mode: Mode = Field(default=Mode.ENFORCE)
    fail_closed: bool = Field(
        default=True,
        description="On internal check errors, treat as a blocking violation rather than allowing.",
    )
    require_tenant: bool = Field(
        default=True, description="Flag writes/reads whose scope has no explicit tenant."
    )
    default_source_trust: TrustLevel = Field(
        default=TrustLevel.UNTRUSTED,
        description="Trust assumed when a caller supplies content with no explicit source (safe default).",
    )

    # Correctness tuning
    duplicate_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    contradiction_enabled: bool = Field(default=True)
    semantic_neighbor_limit: int = Field(
        default=20, ge=0, description="Max existing records fetched to compare a candidate against."
    )

    # Authority tuning
    required_authority_by_namespace: dict[str, float] = Field(
        default_factory=_default_required_authority
    )
    policy_namespace_threshold: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="A namespace requiring at least this authority is treated as a 'policy' namespace.",
    )

    # Security tuning
    redact_secrets: bool = Field(default=True)

    # Protected-backend behaviour
    store_quarantined: bool = Field(
        default=True,
        description="Persist quarantined writes with QUARANTINED status (isolated) instead of dropping.",
    )
    raise_on_blocked_add: bool = Field(
        default=False, description="If True, protected .add raises when a write is blocked."
    )

    # Semantic / LLM
    llm_timeout: float = Field(default=10.0, gt=0.0)
    semantic_fail_open: bool = Field(
        default=True,
        description="If a semantic analyzer errors/times out, skip its findings (True) vs. block (False).",
    )

    # Audit
    audit_content: bool = Field(
        default=True, description="Store a redacted, truncated content preview in audit events."
    )
    audit_content_max_len: int = Field(default=500, ge=0)

    def required_authority(self, namespace: str | None) -> float:
        """Authority required to write into a namespace (0.0 if unrestricted)."""
        if namespace is None:
            return 0.0
        return self.required_authority_by_namespace.get(namespace, 0.0)

    def is_policy_namespace(self, namespace: str | None) -> bool:
        return self.required_authority(namespace) >= self.policy_namespace_threshold


__all__ = ["Config"]
