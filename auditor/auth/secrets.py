"""Secrets backend abstraction (PRD §11.4).

All secret reads (Anthropic key, JWT key, mTLS CA key, agent signing master key) go through a
:class:`SecretsBackend` rather than touching ``os.environ`` directly, so future backends
(Vault, AWS Secrets Manager) are additive. Only :class:`EnvVarBackend` is implemented in v1.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class SecretNotFoundError(KeyError):
    """Raised by :meth:`SecretsBackend.require` when a secret is missing/empty."""


class SecretsBackend(ABC):
    @abstractmethod
    def get(self, name: str) -> str | None:
        """Return the secret value, or ``None`` if absent."""

    def require(self, name: str) -> str:
        """Return the secret value, raising :class:`SecretNotFoundError` if missing/empty."""
        value = self.get(name)
        if not value:
            raise SecretNotFoundError(name)
        return value


class EnvVarBackend(SecretsBackend):
    """Reads secrets from process environment variables (the v1 default)."""

    def get(self, name: str) -> str | None:
        return os.environ.get(name)


def get_secrets_backend(backend: str = "env") -> SecretsBackend:
    """Return the configured secrets backend. Only ``env`` is implemented in v1."""
    if backend == "env":
        return EnvVarBackend()
    raise NotImplementedError(f"secrets backend {backend!r} not implemented in v1 (use 'env')")
