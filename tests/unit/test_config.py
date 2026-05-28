"""Settings load correctly and expose the right defaults/derived properties."""

from __future__ import annotations

from auditor.config import Settings, get_settings


def test_embedding_dim_default_is_384() -> None:
    # Structural default - independent of any env/.env on the machine.
    assert Settings.model_fields["embedding_dim"].default == 384


def test_core_model_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.embedding_backend == "fastembed"
    assert s.judge_model == "claude-haiku-4-5-20251001"
    assert s.agent_model == "claude-sonnet-4-6"
    assert s.crosscheck_model == "claude-sonnet-4-6"
    assert s.secrets_backend == "env"
    assert s.ipc_mtls_enabled is False


def test_judge_live_toggles_on_key() -> None:
    assert Settings(anthropic_api_key=None, _env_file=None).judge_live is False
    assert Settings(anthropic_api_key="sk-ant-test", _env_file=None).judge_live is True


def test_resolved_ipc_transport_is_valid() -> None:
    assert Settings(_env_file=None).resolved_ipc_transport in ("unix", "tcp")


def test_explicit_transport_override() -> None:
    assert Settings(ipc_transport="tcp", _env_file=None).resolved_ipc_transport == "tcp"
    assert Settings(ipc_transport="unix", _env_file=None).resolved_ipc_transport == "unix"


def test_get_settings_is_cached_singleton() -> None:
    assert get_settings() is get_settings()
