"""The :class:`Scope` a memory belongs to (tenant, user, agent, ...)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Scope(BaseModel):
    """Where a memory lives and who may see it.

    Only ``tenant_id`` is required; not every application has users, agents,
    sessions, or namespaces. ``tenant_id`` defaults to ``"default"`` so the
    five-minute path works, but production applications should always set it
    explicitly.

    Example::

        Scope(tenant_id="acme", user_id="alice", namespace="preferences")
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(default="default", description="Hard isolation boundary.")
    user_id: str | None = Field(default=None, description="Owning user, if any.")
    agent_id: str | None = Field(default=None, description="Owning/authoring agent, if any.")
    session_id: str | None = Field(default=None, description="Session the memory came from.")
    namespace: str | None = Field(default=None, description="Logical partition, e.g. 'preferences'.")

    def same_tenant(self, other: Scope) -> bool:
        return self.tenant_id == other.tenant_id

    def readable_by(self, request: Scope) -> bool:
        """Whether a memory in *this* scope may be returned to *request*.

        Enforces the two hard isolation boundaries: tenant, and (when the
        memory is user-scoped) user. Agent/session/namespace are treated as
        soft filters elsewhere, not as isolation boundaries.
        """
        if self.tenant_id != request.tenant_id:
            return False
        return not (self.user_id is not None and self.user_id != request.user_id)

    def as_filter(self) -> dict[str, str]:
        """Non-null scope fields as a flat dict (handy for backend filters)."""
        out: dict[str, str] = {"tenant_id": self.tenant_id}
        for key in ("user_id", "agent_id", "session_id", "namespace"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out


__all__ = ["Scope"]
