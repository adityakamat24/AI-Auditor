"""Harness-side configuration.

The harness reuses the shared :class:`auditor.config.Settings` for IPC connection details (so the two
processes agree on transport) and takes its run/tenant identity from the environment.
"""

from __future__ import annotations

import os
from uuid import UUID

from auditor.config import Settings, get_settings
from auditor.ids import uuid7


def harness_settings() -> Settings:
    return get_settings()


def run_id_from_env() -> UUID:
    val = os.environ.get("HARNESS_RUN_ID")
    return UUID(val) if val else uuid7()


def tenant_id_from_env() -> UUID:
    val = os.environ.get("HARNESS_TENANT_ID")
    return UUID(val) if val else uuid7()
