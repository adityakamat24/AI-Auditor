"""Secrets backend abstraction (PRD §11.4): env-var backend + the additive-backend seam."""

from __future__ import annotations

import pytest
from auditor.auth.secrets import (
    EnvVarBackend,
    SecretNotFoundError,
    get_secrets_backend,
)


def test_env_backend_get_and_require(monkeypatch) -> None:
    monkeypatch.setenv("AUDITOR_TEST_SECRET", "s3cr3t")
    backend = EnvVarBackend()
    assert backend.get("AUDITOR_TEST_SECRET") == "s3cr3t"
    assert backend.require("AUDITOR_TEST_SECRET") == "s3cr3t"


def test_env_backend_missing_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("AUDITOR_ABSENT_SECRET", raising=False)
    assert EnvVarBackend().get("AUDITOR_ABSENT_SECRET") is None


def test_require_raises_on_missing_or_empty(monkeypatch) -> None:
    monkeypatch.delenv("AUDITOR_ABSENT_SECRET", raising=False)
    with pytest.raises(SecretNotFoundError):
        EnvVarBackend().require("AUDITOR_ABSENT_SECRET")
    monkeypatch.setenv("AUDITOR_EMPTY_SECRET", "")
    with pytest.raises(SecretNotFoundError):
        EnvVarBackend().require("AUDITOR_EMPTY_SECRET")


def test_factory_default_is_env() -> None:
    assert isinstance(get_secrets_backend(), EnvVarBackend)
    assert isinstance(get_secrets_backend("env"), EnvVarBackend)


def test_factory_rejects_unimplemented_backends() -> None:
    # The abstraction is additive: Vault/AWS slot in later without a rewrite, but aren't in v1.
    with pytest.raises(NotImplementedError):
        get_secrets_backend("vault")
