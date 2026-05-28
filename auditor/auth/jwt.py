"""JWT issue/verify (PRD §11). STUB - implemented in Phase 2/7.

Issues and verifies the service/session JWTs used to authenticate API and IPC callers. Signing keys come
from the secrets backend (:mod:`auditor.auth.secrets`). ``pyjwt`` is a base dep; it is imported lazily
inside the functions so importing this module stays dependency-light.
"""

from __future__ import annotations

# TODO(phase7): issue/verify JWTs with keys from the secrets backend; enforce aud/iss/exp claims.


def issue_token(claims: dict, *, ttl_seconds: int = 3600) -> str:
    """Issue a signed JWT carrying ``claims``."""
    # import jwt  # lazy (pyjwt) - Phase 7
    raise NotImplementedError("JWT issuance lands in Phase 7")


def verify_token(token: str) -> dict:
    """Verify ``token`` and return its claims, raising on invalid/expired tokens."""
    # import jwt  # lazy (pyjwt) - Phase 7
    raise NotImplementedError("JWT verification lands in Phase 7")


__all__ = ["issue_token", "verify_token"]
