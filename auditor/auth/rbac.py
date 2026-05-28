"""Role-based access control (PRD §11.2). STUB - implemented in Phase 7.

Defines the roles (admin / reviewer / read-only) and the permission checks the API routes depend on,
resolving a verified principal's roles to allowed actions. Enforced as FastAPI dependencies in Phase 7.
"""

from __future__ import annotations

# TODO(phase7): define roles + permission matrix; provide FastAPI dependency for action authorization.
from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    READ_ONLY = "read_only"


def require_role(principal: object, role: Role) -> None:
    """Raise if ``principal`` lacks ``role`` (no-op placeholder until Phase 7)."""
    raise NotImplementedError("RBAC enforcement lands in Phase 7")


__all__ = ["Role", "require_role"]
