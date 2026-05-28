"""Detector registry + lifecycle state (PRD §9.13).

Newly registered detectors default to ``PROPOSED`` - this structurally enforces the rule that nobody
(including Claude Code) can ship a detector straight to ``ENFORCING``. The full state machine and
promotion criteria are implemented in Phase 8; this registry establishes the seam.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum


class DetectorState(StrEnum):
    PROPOSED = "PROPOSED"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    ENFORCING = "ENFORCING"
    DISABLED = "DISABLED"
    DEPRECATED = "DEPRECATED"
    REMOVED = "REMOVED"


@dataclass
class DetectorRegistration:
    name: str
    version: str
    asi_category: str
    factory: Callable[..., object]
    requires_judge: bool = False
    state: DetectorState = DetectorState.PROPOSED


_REGISTRY: dict[str, DetectorRegistration] = {}


def register_detector(
    name: str,
    version: str,
    asi_category: str,
    *,
    requires_judge: bool = False,
    state: DetectorState = DetectorState.PROPOSED,
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Decorator that registers a detector factory. New detectors start in ``PROPOSED``."""

    def decorator(factory: Callable[..., object]) -> Callable[..., object]:
        _REGISTRY[name] = DetectorRegistration(
            name=name,
            version=version,
            asi_category=asi_category,
            factory=factory,
            requires_judge=requires_judge,
            state=state,
        )
        return factory

    return decorator


def get_registry() -> dict[str, DetectorRegistration]:
    """Return a copy of the current detector registry."""
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Clear the registry (used by tests)."""
    _REGISTRY.clear()


__all__ = [
    "DetectorState",
    "DetectorRegistration",
    "register_detector",
    "get_registry",
    "clear_registry",
]
