"""Runtime sampler policy (PRD §5.4) - user-configurable from the UI / admin API.

A single, process-wide, mutable sampling policy the reviewer adjusts at runtime:

- ``percentage``  - L1 hard triggers + a stratified deterministic sample at ``rate`` (the PRD default).
- ``every_nth``   - L1 hard triggers + every Nth run (deterministic counter).
- ``interval``    - L1 hard triggers + at most one audited run per ``interval_seconds``.
- ``always``      - audit every run.
- ``never``       - audit nothing (truly off; intended for demo control, not for production).

Hard-trigger L1 audits (channel divergence, cheap-risk above threshold, sensitive data outside the
allowlist, recent-incident tenants) still fire in every mode except ``never``. The orchestrator + judge
still run for any sampled run; this module ONLY decides whether to enter the deep pipeline.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from typing import Literal
from uuid import UUID

from auditor.async_pipeline.sampler import RunSignals, SamplerDecision, stable_hash

SamplerMode = Literal["percentage", "every_nth", "interval", "always", "never"]
_VALID_MODES = ("percentage", "every_nth", "interval", "always", "never")


@dataclass
class SamplerSettings:
    """The user-facing sampler configuration. All fields are validated on update."""

    mode: SamplerMode = "percentage"
    rate: float = 0.05  # used by mode=percentage (0.0–1.0)
    every_n: int = 10  # used by mode=every_nth (>= 1)
    interval_seconds: float = 60.0  # used by mode=interval (> 0)
    critical_risk_threshold: int = 70  # the L1 cheap-risk cutoff (0–100)


# Process-wide mutable state. Audit decisions read from these.
_state_lock = threading.Lock()
_settings: SamplerSettings = SamplerSettings()
_counter: int = 0  # every_nth counter
_last_audit_ts: float = 0.0  # interval throttle


def _validate(settings: SamplerSettings) -> None:
    if settings.mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}, got {settings.mode!r}")
    if not (0.0 <= settings.rate <= 1.0):
        raise ValueError(f"rate must be in [0,1], got {settings.rate}")
    if settings.every_n < 1:
        raise ValueError(f"every_n must be >= 1, got {settings.every_n}")
    if settings.interval_seconds <= 0:
        raise ValueError(f"interval_seconds must be > 0, got {settings.interval_seconds}")
    if not (0 <= settings.critical_risk_threshold <= 100):
        raise ValueError(f"critical_risk_threshold must be in [0,100], got {settings.critical_risk_threshold}")


def get_settings_snapshot() -> SamplerSettings:
    """Return a copy of the current settings (safe to mutate)."""
    with _state_lock:
        return SamplerSettings(**asdict(_settings))


def set_settings(new: SamplerSettings) -> SamplerSettings:
    """Atomically replace the runtime settings; resets the every_nth counter + interval throttle."""
    _validate(new)
    global _settings, _counter, _last_audit_ts
    with _state_lock:
        _settings = SamplerSettings(**asdict(new))
        _counter = 0
        _last_audit_ts = 0.0
        return SamplerSettings(**asdict(_settings))


def decide(run_id: UUID, tenant_id: UUID, signals: RunSignals) -> SamplerDecision:
    """The user-configurable sampler decision. L1 hard triggers + the selected mode for L2."""
    settings = get_settings_snapshot()

    # `never` truly skips everything - including the L1 hard triggers. Use with care.
    if settings.mode == "never":
        return SamplerDecision(tier="NONE", reason="sampler off (mode=never)", audit=False, judge_allowed=False)

    # L1 hard triggers - always audit when they fire (any mode except `never`).
    if signals.channel_divergence:
        return SamplerDecision("L1", "channel divergence", True, True)
    if signals.cheap_risk_score >= settings.critical_risk_threshold:
        return SamplerDecision("L1", f"cheap risk score {signals.cheap_risk_score}", True, True)
    if signals.touched_sensitive_data and not signals.in_allowlisted_path:
        return SamplerDecision("L1", "sensitive data outside allowlist", True, True)
    if signals.tenant_recent_incident_count > 0:
        return SamplerDecision("L1", "recent tenant incidents", True, True)

    # Mode-driven L2 decision.
    if settings.mode == "always":
        return SamplerDecision("L2", "mode=always (every run audited)", True, True)

    if settings.mode == "every_nth":
        global _counter
        with _state_lock:
            _counter += 1
            current = _counter
        if (current % settings.every_n) == 0:
            return SamplerDecision("L2", f"every {settings.every_n}th run (#{current})", True, True)
        return SamplerDecision(
            "NONE", f"skip - run #{current} is not a multiple of {settings.every_n}", False, False,
        )

    if settings.mode == "interval":
        global _last_audit_ts
        with _state_lock:
            now = time.time()
            elapsed = now - _last_audit_ts
            should_audit = elapsed >= settings.interval_seconds
            if should_audit:
                _last_audit_ts = now
        if should_audit:
            return SamplerDecision(
                "L2", f"audit window elapsed ({settings.interval_seconds:.0f}s)", True, True,
            )
        return SamplerDecision(
            "NONE",
            f"within interval (last audit {elapsed:.0f}s ago, window {settings.interval_seconds:.0f}s)",
            False, False,
        )

    # mode == "percentage" (default): stratified deterministic sample
    bucket = stable_hash(f"{tenant_id}:{signals.tool_category}:{run_id}") % 10_000
    if bucket < int(settings.rate * 10_000):
        return SamplerDecision(
            "L2", f"stratified at {settings.rate:.2%}", True, True, settings.rate,
        )
    return SamplerDecision(
        "NONE", f"skip - not sampled (rate {settings.rate:.2%})", False, False, settings.rate,
    )


def reset_for_tests() -> None:
    """Reset runtime state - for unit tests only."""
    global _settings, _counter, _last_audit_ts
    with _state_lock:
        _settings = SamplerSettings()
        _counter = 0
        _last_audit_ts = 0.0


__all__ = [
    "SamplerMode",
    "SamplerSettings",
    "get_settings_snapshot",
    "set_settings",
    "decide",
    "reset_for_tests",
]
