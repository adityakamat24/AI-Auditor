"""Every auditor/harness submodule imports cleanly.

Guards against a later-phase stub importing a heavy/optional dependency at module top level
(presidio, spaCy, AG2, anthropic, litellm, pywin32, fastembed, ...) which would break a base install.
"""

from __future__ import annotations

import importlib
import pkgutil

import auditor
import harness


def _module_names(package) -> list[str]:
    names: list[str] = []
    for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        # Alembic env/versions are not importable outside an Alembic run.
        if ".migrations" in info.name:
            continue
        names.append(info.name)
    return names


def test_all_auditor_and_harness_modules_import() -> None:
    failures: dict[str, str] = {}
    for package in (auditor, harness):
        for name in _module_names(package):
            try:
                importlib.import_module(name)
            except Exception as exc:  # noqa: BLE001 - collect every failure
                failures[name] = repr(exc)
    assert not failures, f"modules failed to import: {failures}"
