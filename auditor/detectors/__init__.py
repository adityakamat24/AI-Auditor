"""Detectors: ABC + lifecycle registry now; the ten ASI detectors land in Phase 4."""

from auditor.detectors.base import Detector, Trace
from auditor.detectors.registry import (
    DetectorRegistration,
    DetectorState,
    clear_registry,
    get_registry,
    register_detector,
)

__all__ = [
    "Detector",
    "Trace",
    "DetectorRegistration",
    "DetectorState",
    "clear_registry",
    "get_registry",
    "register_detector",
]
