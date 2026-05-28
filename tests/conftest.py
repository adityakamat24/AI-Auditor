"""Shared pytest fixtures.

Unit tests must NOT require live backing services (Postgres/Redis/MinIO/OPA) — all I/O is mocked or
stubbed. Integration tests (Phase 2+) opt in via the ``integration`` marker.
"""

from __future__ import annotations

import pytest
from auditor.config import Settings


@pytest.fixture
def settings() -> Settings:
    """A Settings instance that ignores any local .env so unit tests are hermetic."""
    return Settings(_env_file=None)


@pytest.fixture(autouse=True)
def _offline_judge(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the deterministic offline stub judge for all non-integration tests.

    Judge-driven detectors call :func:`auditor.judge.client.get_judge`, which selects the live
    ``LiteLLMJudge`` whenever ``ANTHROPIC_API_KEY`` is present (e.g. in a real ``.env``). Unit/red-team
    tests must be hermetic — independent of local env and never making real (paid, non-deterministic) LLM
    calls — so we point the judge factory's settings at a key-less Settings, which selects the offline
    stub. Integration tests opt out via the ``integration`` marker and may exercise the live judge.
    """
    if request.node.get_closest_marker("integration"):
        return
    monkeypatch.setattr(
        "auditor.judge.client.get_settings",
        lambda: Settings(anthropic_api_key=None, _env_file=None),
    )
