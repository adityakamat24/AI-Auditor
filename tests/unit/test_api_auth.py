"""Unit tests for auditor.api.auth (P5 minimal auth layer).

Covers:
  - issue_token → verify_token round-trip.
  - Expired token is rejected.
  - Tampered signature is rejected.
  - FastAPI dependency ``require_role``: 401 (no token), 403 (wrong role), 200 (right role).
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from auditor.api.auth import (
    AuthError,
    issue_token,
    require_role,
    verify_token,
)
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- helpers


def _make_token(*, role: str = "reviewer", ttl_s: int = 3600) -> str:
    return issue_token(
        user_id="user-001",
        tenant_id="tenant-001",
        role=role,
        ttl_s=ttl_s,
    )


def _mini_app(*required_roles: str) -> tuple[FastAPI, str]:
    """Return a FastAPI app with a single protected route and the path string."""
    app = FastAPI()
    path = "/protected"

    @app.get(path)
    async def _protected(claims: dict = Depends(require_role(*required_roles))):
        return {"role": claims["role"]}

    return app, path


# ------------------------------------------------------------------------------- round-trip


def test_issue_and_verify_round_trip() -> None:
    token = issue_token(user_id="u1", tenant_id="t1", role="admin")
    claims = verify_token(token)
    assert claims["sub"] == "u1"
    assert claims["tenant_id"] == "t1"
    assert claims["role"] == "admin"
    assert "exp" in claims and "iat" in claims


def test_all_roles_round_trip() -> None:
    for role in ("admin", "reviewer", "readonly"):
        token = issue_token(user_id="u", tenant_id="t", role=role)
        claims = verify_token(token)
        assert claims["role"] == role


def test_claims_contain_exp_in_future() -> None:
    token = issue_token(user_id="u", tenant_id="t", role="readonly", ttl_s=600)
    claims = verify_token(token)
    assert claims["exp"] > time.time()


# ------------------------------------------------------------------------------- expiry


def test_expired_token_is_rejected() -> None:
    # Issue a token that expires in the past by using a very short TTL and fast-forwarding time.
    token = issue_token(user_id="u", tenant_id="t", role="admin", ttl_s=1)
    # Patch time.time to be well past the expiry.
    with patch("auditor.api.auth.time") as mock_time:
        mock_time.time.return_value = time.time() + 10_000
        with pytest.raises(AuthError, match="expired"):
            verify_token(token)


def test_zero_ttl_token_is_already_expired() -> None:
    # Issue with ttl=0; exp == iat; verify should fail immediately.
    token = issue_token(user_id="u", tenant_id="t", role="readonly", ttl_s=0)
    with pytest.raises(AuthError, match="expired"):
        verify_token(token)


# ------------------------------------------------------------------------------- signature tampering


def test_tampered_payload_is_rejected() -> None:
    token = _make_token()
    parts = token.split(".")
    # Replace last char of the payload segment to break the signature.
    parts[1] = parts[1][:-1] + ("Z" if parts[1][-1] != "Z" else "A")
    tampered = ".".join(parts)
    with pytest.raises(AuthError, match="invalid"):
        verify_token(tampered)


def test_tampered_signature_is_rejected() -> None:
    token = _make_token()
    parts = token.split(".")
    parts[2] = parts[2][:-1] + ("Z" if parts[2][-1] != "Z" else "A")
    tampered = ".".join(parts)
    with pytest.raises(AuthError, match="invalid"):
        verify_token(tampered)


def test_truncated_token_is_rejected() -> None:
    with pytest.raises(AuthError, match="malformed"):
        verify_token("only.two")


def test_empty_string_is_rejected() -> None:
    with pytest.raises(AuthError):
        verify_token("")


# ------------------------------------------------------------------------------- FastAPI dependency: 401 (no token)


def test_no_token_returns_401() -> None:
    app, path = _mini_app("reviewer")
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(path)
    assert resp.status_code == 401


def test_invalid_token_returns_401() -> None:
    app, path = _mini_app("reviewer")
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(path, headers={"Authorization": "Bearer not.a.valid.token"})
    assert resp.status_code == 401


# ------------------------------------------------------------------------------- FastAPI dependency: 403 (wrong role)


def test_wrong_role_returns_403() -> None:
    app, path = _mini_app("admin")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="readonly")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_reviewer_cannot_access_admin_only_route() -> None:
    app, path = _mini_app("admin")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="reviewer")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ------------------------------------------------------------------------------- FastAPI dependency: 200 (right role)


def test_correct_role_returns_200() -> None:
    app, path = _mini_app("reviewer")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="reviewer")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "reviewer"


def test_admin_can_access_multi_role_route() -> None:
    app, path = _mini_app("admin", "reviewer")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="admin")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_reviewer_can_access_multi_role_route() -> None:
    app, path = _mini_app("admin", "reviewer")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="reviewer")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_session_cookie_is_accepted() -> None:
    """Token in ``session`` cookie (HTTP-only) is also honoured."""
    app, path = _mini_app("readonly")
    client = TestClient(app, raise_server_exceptions=False)
    token = issue_token(user_id="u", tenant_id="t", role="readonly")
    resp = client.get(path, cookies={"session": token})
    assert resp.status_code == 200
