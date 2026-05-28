"""OIDC integration (PRD §11.1). STUB — implemented in Phase 7.

Optional single sign-on: validates OIDC ID tokens from an external IdP and maps claims to local roles. Uses
``authlib`` (the ``[auth]`` extra), imported lazily inside the methods so this module imports without it.
"""

from __future__ import annotations

# TODO(phase7): validate OIDC ID tokens via authlib; map IdP claims -> local roles.


class OidcAuthenticator:
    """Validates OIDC tokens and maps claims to local principals."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._args = args
        self._kwargs = kwargs

    async def verify(self, id_token: str) -> dict:
        """Validate an OIDC ID token and return the mapped principal claims."""
        # from authlib.jose import jwt  # lazy — Phase 7, [auth] extra
        raise NotImplementedError("OIDC integration lands in Phase 7")


__all__ = ["OidcAuthenticator"]
