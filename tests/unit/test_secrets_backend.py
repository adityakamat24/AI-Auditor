"""SecretsBackend: env reads, require() raises on missing, factory selection."""

from __future__ import annotations

import pytest
from auditor.auth.secrets import EnvVarBackend, SecretNotFoundError, get_secrets_backend


def test_envvar_get_and_require(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "s3cr3t")
    backend = EnvVarBackend()
    assert backend.get("MY_SECRET") == "s3cr3t"
    assert backend.require("MY_SECRET") == "s3cr3t"


def test_envvar_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOPE_SECRET", raising=False)
    backend = EnvVarBackend()
    assert backend.get("NOPE_SECRET") is None
    with pytest.raises(SecretNotFoundError):
        backend.require("NOPE_SECRET")


def test_factory_env_and_unknown() -> None:
    assert isinstance(get_secrets_backend("env"), EnvVarBackend)
    with pytest.raises(NotImplementedError):
        get_secrets_backend("vault")
