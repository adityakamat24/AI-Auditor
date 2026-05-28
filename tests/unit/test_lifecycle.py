"""Unit tests for the detector lifecycle state machine (PRD §9.13).

Covers:
- Legal transition PROPOSED -> SHADOW (records row + audit entry).
- Illegal transition PROPOSED -> ENFORCING raises LifecycleError.
- SHADOW -> CANARY blocked when precision < 0.80, blocked when fp_rate missing,
  blocked when days < 7, allowed when all criteria met (with force=True for days gate).
- All transitions are audited via a fake writer.
- current_state() defaults to PROPOSED when no rows exist.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from auditor.detectors.lifecycle import (
    DetectorLifecycle,
    InMemoryLifecycleStore,
    LifecycleError,
)
from auditor.detectors.registry import DetectorState

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_lc(
    store: InMemoryLifecycleStore | None = None,
    audit: object | None = None,
) -> tuple[DetectorLifecycle, InMemoryLifecycleStore, list[dict]]:
    """Return (lifecycle, store, audit_calls)."""
    store = store or InMemoryLifecycleStore()
    audit_calls: list[dict] = []

    class _FakeAudit:
        async def append(self, tenant_id, *, actor_type, action, actor_id, target_type, target_id, payload):
            audit_calls.append(
                {
                    "tenant_id": tenant_id,
                    "actor_type": actor_type,
                    "action": action,
                    "actor_id": actor_id,
                    "payload": payload,
                }
            )
            return b""

    lc = DetectorLifecycle(store=store, audit_writer=_FakeAudit())
    return lc, store, audit_calls


DETECTOR = "asi01_goal_hijack"
VERSION = "1.0.0"
ADMIN_ID = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# current_state defaults
# ---------------------------------------------------------------------------


async def test_current_state_defaults_to_proposed() -> None:
    lc, _, _ = _make_lc()
    state = await lc.current_state(DETECTOR, VERSION)
    assert state == DetectorState.PROPOSED


# ---------------------------------------------------------------------------
# Legal transition: PROPOSED -> SHADOW
# ---------------------------------------------------------------------------


async def test_proposed_to_shadow_succeeds() -> None:
    lc, store, audit_calls = _make_lc()
    result = await lc.transition(
        DETECTOR,
        VERSION,
        DetectorState.SHADOW,
        actor_id=ADMIN_ID,
        rationale="Tests green, code reviewed",
    )
    assert result == DetectorState.SHADOW
    # Verify a lifecycle row was written.
    assert len(store.rows) == 1
    row = store.rows[0]
    assert row["detector"] == DETECTOR
    assert row["version"] == VERSION
    assert row["state"] == "SHADOW"
    assert row["previous_state"] == "PROPOSED"
    assert row["rationale"] == "Tests green, code reviewed"
    # Verify audit entry was appended.
    assert len(audit_calls) == 1
    entry = audit_calls[0]
    assert entry["action"] == "detector_lifecycle_transition"
    assert entry["payload"]["previous_state"] == "PROPOSED"
    assert entry["payload"]["new_state"] == "SHADOW"


async def test_proposed_to_shadow_no_admin_required() -> None:
    """PROPOSED->SHADOW does not require admin_approval per policy."""
    lc, store, _ = _make_lc()
    result = await lc.transition(DETECTOR, VERSION, DetectorState.SHADOW)
    assert result == DetectorState.SHADOW
    assert len(store.rows) == 1


# ---------------------------------------------------------------------------
# Illegal transition
# ---------------------------------------------------------------------------


async def test_proposed_to_enforcing_is_illegal() -> None:
    lc, _, _ = _make_lc()
    with pytest.raises(LifecycleError, match="not a legal lifecycle transition"):
        await lc.transition(DETECTOR, VERSION, DetectorState.ENFORCING)


async def test_proposed_to_canary_is_illegal() -> None:
    lc, _, _ = _make_lc()
    with pytest.raises(LifecycleError, match="not a legal lifecycle transition"):
        await lc.transition(DETECTOR, VERSION, DetectorState.CANARY)


async def test_proposed_to_disabled_is_illegal() -> None:
    lc, _, _ = _make_lc()
    with pytest.raises(LifecycleError, match="not a legal lifecycle transition"):
        await lc.transition(DETECTOR, VERSION, DetectorState.DISABLED)


# ---------------------------------------------------------------------------
# SHADOW -> CANARY gates
# ---------------------------------------------------------------------------


async def _shadow_store(store: InMemoryLifecycleStore, days_ago: float = 8.0) -> None:
    """Pre-populate store with a SHADOW row inserted `days_ago` days ago."""
    store.rows.append(
        {
            "id": str(uuid.uuid4()),
            "detector": DETECTOR,
            "version": VERSION,
            "state": "SHADOW",
            "previous_state": "PROPOSED",
            "rationale": "pre-seeded",
            "metrics_snapshot": None,
            "changed_by": ADMIN_ID,
            "tenant_id": None,
            "canary_partition": None,
            "changed_at": datetime.now(tz=UTC) - timedelta(days=days_ago),
        }
    )


async def test_shadow_to_canary_blocked_precision_too_low() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="precision"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.CANARY,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.75, "fp_rate": 0.03},
        )


async def test_shadow_to_canary_blocked_fp_rate_too_high() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="fp_rate"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.CANARY,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.85, "fp_rate": 0.08},
        )


async def test_shadow_to_canary_blocked_too_few_days() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=3)  # only 3 days, need 7
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="7 days"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.CANARY,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.85, "fp_rate": 0.03},
        )


async def test_shadow_to_canary_blocked_missing_fp_rate() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="fp_rate"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.CANARY,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.85},  # fp_rate missing
        )


async def test_shadow_to_canary_blocked_no_admin_id() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="admin approval"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.CANARY,
            # actor_id NOT provided
            metrics={"precision": 0.85, "fp_rate": 0.03},
        )


async def test_shadow_to_canary_allowed_when_criteria_met() -> None:
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=8)
    lc, store2, audit_calls = _make_lc(store)
    result = await lc.transition(
        DETECTOR,
        VERSION,
        DetectorState.CANARY,
        actor_id=ADMIN_ID,
        rationale="7 days done, precision 0.82",
        metrics={"precision": 0.82, "fp_rate": 0.04},
    )
    assert result == DetectorState.CANARY
    # New row + audit entry written.
    canary_rows = [r for r in store.rows if r["state"] == "CANARY"]
    assert len(canary_rows) == 1
    assert canary_rows[0]["canary_partition"] is not None  # default from policy
    assert len(audit_calls) == 1


async def test_shadow_to_canary_force_skips_day_gate() -> None:
    """force=True bypasses all gates (used by calibration system)."""
    store = InMemoryLifecycleStore()
    await _shadow_store(store, days_ago=2)  # only 2 days
    lc, _, _ = _make_lc(store)
    result = await lc.transition(
        DETECTOR,
        VERSION,
        DetectorState.CANARY,
        force=True,
        metrics={"precision": 0.81, "fp_rate": 0.04},
    )
    assert result == DetectorState.CANARY


# ---------------------------------------------------------------------------
# CANARY -> ENFORCING gates
# ---------------------------------------------------------------------------


async def _canary_store(store: InMemoryLifecycleStore, days_ago: float = 8.0) -> None:
    store.rows.append(
        {
            "id": str(uuid.uuid4()),
            "detector": DETECTOR,
            "version": VERSION,
            "state": "CANARY",
            "previous_state": "SHADOW",
            "rationale": "pre-seeded",
            "metrics_snapshot": None,
            "changed_by": ADMIN_ID,
            "tenant_id": None,
            "canary_partition": 0.05,
            "changed_at": datetime.now(tz=UTC) - timedelta(days=days_ago),
        }
    )


async def test_canary_to_enforcing_allowed_when_criteria_met() -> None:
    store = InMemoryLifecycleStore()
    await _canary_store(store, days_ago=8)
    lc, _, audit_calls = _make_lc(store)
    result = await lc.transition(
        DETECTOR,
        VERSION,
        DetectorState.ENFORCING,
        actor_id=ADMIN_ID,
        rationale="8 days canary, precision 0.88, no incidents",
        metrics={"precision": 0.88, "critical_incidents": 0},
    )
    assert result == DetectorState.ENFORCING
    assert len(audit_calls) == 1


async def test_canary_to_enforcing_blocked_on_critical_incidents() -> None:
    store = InMemoryLifecycleStore()
    await _canary_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="critical incident"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.ENFORCING,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.88, "critical_incidents": 1},
        )


async def test_canary_to_enforcing_blocked_precision_too_low() -> None:
    store = InMemoryLifecycleStore()
    await _canary_store(store, days_ago=8)
    lc, _, _ = _make_lc(store)
    with pytest.raises(LifecycleError, match="precision"):
        await lc.transition(
            DETECTOR,
            VERSION,
            DetectorState.ENFORCING,
            actor_id=ADMIN_ID,
            metrics={"precision": 0.82, "critical_incidents": 0},
        )


# ---------------------------------------------------------------------------
# Auto-disable: ENFORCING -> DISABLED
# ---------------------------------------------------------------------------


async def _enforcing_store(store: InMemoryLifecycleStore) -> None:
    store.rows.append(
        {
            "id": str(uuid.uuid4()),
            "detector": DETECTOR,
            "version": VERSION,
            "state": "ENFORCING",
            "previous_state": "CANARY",
            "rationale": "pre-seeded",
            "metrics_snapshot": None,
            "changed_by": ADMIN_ID,
            "tenant_id": None,
            "canary_partition": None,
            "changed_at": datetime.now(tz=UTC) - timedelta(days=30),
        }
    )


async def test_enforcing_to_disabled_auto_no_admin_required() -> None:
    """Auto-disable by calibration system needs no actor_id (force=True or no admin gate)."""
    store = InMemoryLifecycleStore()
    await _enforcing_store(store)
    lc, _, audit_calls = _make_lc(store)
    result = await lc.transition(
        DETECTOR,
        VERSION,
        DetectorState.DISABLED,
        rationale="3 consecutive nightly runs below 0.85",
    )
    assert result == DetectorState.DISABLED
    assert len(audit_calls) == 1
    entry = audit_calls[0]
    assert entry["actor_type"] == "system"
