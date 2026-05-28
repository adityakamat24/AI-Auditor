"""Detector lifecycle state machine (PRD §9.13).

Governs promotion of a detector through PROPOSED -> SHADOW -> CANARY -> ENFORCING
(and DISABLED/DEPRECATED/REMOVED), enforcing the calibration gates from
``detector_lifecycle_policy.yaml`` before each transition.

Every state change is written to the ``detector_lifecycle`` table AND appended to the
hash-chained audit log via :class:`~auditor.audit_log.writer.AuditLogWriter`.

Design notes
~~~~~~~~~~~~
- The ``session_factory`` and ``audit_writer`` are injected so tests can supply
  in-memory fakes without touching any real database or Postgres advisory locks.
- ``current_state`` reads the most recent row for (detector, version); when no row
  exists the default is ``PROPOSED``.
- Gates are loaded from ``detector_lifecycle_policy.yaml`` at import time.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import yaml

from auditor.detectors.registry import DetectorState

# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

_POLICY_PATH = Path(__file__).parent / "detector_lifecycle_policy.yaml"


def _load_policy() -> dict[str, Any]:
    with _POLICY_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


_POLICY: dict[str, Any] = _load_policy()

# ---------------------------------------------------------------------------
# Legal transition graph
# ---------------------------------------------------------------------------

# Maps (from_state, to_state) -> policy key in _POLICY["transitions"].
LEGAL_TRANSITIONS: dict[tuple[str, str], str] = {
    (DetectorState.PROPOSED, DetectorState.SHADOW): "PROPOSED->SHADOW",
    (DetectorState.SHADOW, DetectorState.CANARY): "SHADOW->CANARY",
    (DetectorState.CANARY, DetectorState.ENFORCING): "CANARY->ENFORCING",
    (DetectorState.ENFORCING, DetectorState.DISABLED): "ENFORCING->DISABLED",
    (DetectorState.ENFORCING, DetectorState.DEPRECATED): "ENFORCING->DEPRECATED",
    (DetectorState.DISABLED, DetectorState.SHADOW): "DISABLED->SHADOW",
    (DetectorState.DEPRECATED, DetectorState.REMOVED): "DEPRECATED->REMOVED",
}

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LifecycleError(RuntimeError):
    """Raised on an illegal or ungated detector lifecycle transition."""


# ---------------------------------------------------------------------------
# Storage & audit protocols (allow injection of fakes in tests)
# ---------------------------------------------------------------------------


class LifecycleStore(Protocol):
    """Persist a lifecycle row and query the current state."""

    async def write(
        self,
        *,
        detector: str,
        version: str,
        state: str,
        previous_state: str | None,
        rationale: str | None,
        metrics_snapshot: dict | None,
        changed_by: str | None,
        tenant_id: str | None,
        canary_partition: float | None,
    ) -> None:
        """Write a new lifecycle transition row."""

    async def latest_state(
        self, detector: str, version: str
    ) -> tuple[str, datetime | None]:
        """Return (current_state_str, entered_at) or (PROPOSED, None) if no rows."""


class AuditWriter(Protocol):
    """Subset of AuditLogWriter used by the lifecycle machine."""

    async def append(
        self,
        tenant_id: uuid.UUID,
        *,
        actor_type: str,
        action: str,
        actor_id: uuid.UUID | None,
        target_type: str | None,
        target_id: uuid.UUID | None,
        payload: dict | None,
    ) -> bytes:
        """Append an audit-log entry."""


# ---------------------------------------------------------------------------
# In-memory store (for tests)
# ---------------------------------------------------------------------------


class InMemoryLifecycleStore:
    """A fake LifecycleStore backed by an in-memory list; no DB required."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def write(
        self,
        *,
        detector: str,
        version: str,
        state: str,
        previous_state: str | None,
        rationale: str | None,
        metrics_snapshot: dict | None,
        changed_by: str | None,
        tenant_id: str | None,
        canary_partition: float | None,
    ) -> None:
        self.rows.append(
            {
                "id": str(uuid.uuid4()),
                "detector": detector,
                "version": version,
                "state": state,
                "previous_state": previous_state,
                "rationale": rationale,
                "metrics_snapshot": metrics_snapshot,
                "changed_by": changed_by,
                "tenant_id": tenant_id,
                "canary_partition": canary_partition,
                "changed_at": datetime.now(tz=UTC),
            }
        )

    async def latest_state(
        self, detector: str, version: str
    ) -> tuple[str, datetime | None]:
        matches = [
            r for r in self.rows if r["detector"] == detector and r["version"] == version
        ]
        if not matches:
            return (str(DetectorState.PROPOSED), None)
        latest = max(matches, key=lambda r: r["changed_at"])
        return (latest["state"], latest["changed_at"])


# ---------------------------------------------------------------------------
# Real SQLAlchemy store
# ---------------------------------------------------------------------------


class DbLifecycleStore:
    """Production LifecycleStore backed by the ``detector_lifecycle`` table."""

    def __init__(self, session_factory: Any) -> None:
        self._sf = session_factory

    async def write(
        self,
        *,
        detector: str,
        version: str,
        state: str,
        previous_state: str | None,
        rationale: str | None,
        metrics_snapshot: dict | None,
        changed_by: str | None,
        tenant_id: str | None,
        canary_partition: float | None,
    ) -> None:
        from auditor.db.models import DetectorLifecycle as LifecycleRow

        row = LifecycleRow(
            id=str(uuid.uuid4()),
            detector=detector,
            version=version,
            state=state,
            tenant_id=tenant_id,
            canary_partition=canary_partition,
            previous_state=previous_state,
            rationale=rationale,
            metrics_snapshot=metrics_snapshot,
            changed_by=changed_by,
        )
        async with self._sf() as session, session.begin():
            session.add(row)

    async def latest_state(
        self, detector: str, version: str
    ) -> tuple[str, datetime | None]:
        from sqlalchemy import select

        from auditor.db.models import DetectorLifecycle as LifecycleRow

        async with self._sf() as session:
            result = await session.execute(
                select(LifecycleRow.state, LifecycleRow.changed_at)
                .where(
                    LifecycleRow.detector == detector,
                    LifecycleRow.version == version,
                )
                .order_by(LifecycleRow.changed_at.desc())
                .limit(1)
            )
            row = result.first()
            if row is None:
                return (str(DetectorState.PROPOSED), None)
            return (row.state, row.changed_at)


# ---------------------------------------------------------------------------
# Null audit writer (for contexts without a real tenant, e.g. pure unit tests)
# ---------------------------------------------------------------------------


class NullAuditWriter:
    """Discards all audit entries (used when no real audit log is needed)."""

    async def append(self, *args: object, **kwargs: object) -> bytes:
        return b""


# ---------------------------------------------------------------------------
# Gate validation helpers
# ---------------------------------------------------------------------------


def _check_gates(
    policy_key: str,
    *,
    metrics: dict | None,
    days_in_state: float,
    actor_id: str | None,
    force: bool,
) -> None:
    """Raise LifecycleError if the policy gates for *policy_key* are not satisfied."""
    if force:
        return

    gates = _POLICY["transitions"][policy_key]

    # min_days gate
    min_days: int = gates.get("min_days", 0) or 0
    if min_days > 0 and days_in_state < min_days:
        raise LifecycleError(
            f"Transition {policy_key!r} requires at least {min_days} days in current "
            f"state; only {days_in_state:.1f} days elapsed."
        )

    # admin_approval gate
    if gates.get("admin_approval") and not actor_id:
        raise LifecycleError(
            f"Transition {policy_key!r} requires admin approval (actor_id must be provided)."
        )

    m = metrics or {}

    # precision_min gate
    precision_min = gates.get("precision_min")
    if precision_min is not None:
        observed = m.get("precision")
        if observed is None:
            raise LifecycleError(
                f"Transition {policy_key!r} requires a 'precision' metric "
                f"(>= {precision_min}), but none was supplied."
            )
        if observed < precision_min:
            raise LifecycleError(
                f"Transition {policy_key!r} requires precision >= {precision_min}; "
                f"observed {observed}."
            )

    # fp_rate_max gate
    fp_rate_max = gates.get("fp_rate_max")
    if fp_rate_max is not None:
        observed_fp = m.get("fp_rate")
        if observed_fp is None:
            raise LifecycleError(
                f"Transition {policy_key!r} requires a 'fp_rate' metric "
                f"(<= {fp_rate_max}), but none was supplied."
            )
        if observed_fp > fp_rate_max:
            raise LifecycleError(
                f"Transition {policy_key!r} requires fp_rate <= {fp_rate_max}; "
                f"observed {observed_fp}."
            )

    # no_critical_incidents gate
    if gates.get("no_critical_incidents"):
        critical = m.get("critical_incidents", 0)
        if critical > 0:
            raise LifecycleError(
                f"Transition {policy_key!r} requires zero critical incidents; "
                f"found {critical}."
            )


# ---------------------------------------------------------------------------
# Main lifecycle manager
# ---------------------------------------------------------------------------

# Sentinel UUID used for system-actor audit entries when no tenant is known.
_SYSTEM_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


class DetectorLifecycle:
    """Validates and applies detector state transitions against calibration gates.

    Parameters
    ----------
    store:
        Where lifecycle rows are persisted.  Defaults to an in-memory store so
        the class is usable without a database (e.g., in unit tests).
    audit_writer:
        Where audit-log entries are appended.  Defaults to a no-op writer.
    default_tenant_id:
        UUID used for audit-log entries when no per-transition tenant is given.
    """

    def __init__(
        self,
        store: LifecycleStore | None = None,
        audit_writer: AuditWriter | None = None,
        default_tenant_id: uuid.UUID | None = None,
    ) -> None:
        self._store: LifecycleStore = store or InMemoryLifecycleStore()
        self._audit: AuditWriter = audit_writer or NullAuditWriter()
        self._default_tenant = default_tenant_id or _SYSTEM_TENANT

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def current_state(self, detector: str, version: str) -> DetectorState:
        """Return the current :class:`DetectorState` for the given detector+version."""
        state_str, _ = await self._store.latest_state(detector, version)
        return DetectorState(state_str)

    async def transition(
        self,
        detector: str,
        version: str,
        target: DetectorState,
        *,
        actor_id: str | None = None,
        rationale: str | None = None,
        metrics: dict | None = None,
        force: bool = False,
        tenant_id: uuid.UUID | None = None,
        canary_partition: float | None = None,
    ) -> DetectorState:
        """Promote or demote *detector@version* to *target*.

        Parameters
        ----------
        detector:
            Detector name (e.g. ``"asi01_goal_hijack"``).
        version:
            Semver string (e.g. ``"1.0.0"``).
        target:
            The desired :class:`DetectorState`.
        actor_id:
            UUID string of the admin user triggering this change (required for
            transitions that need admin_approval).
        rationale:
            Free-text reason for the transition (stored in the DB row and audit log).
        metrics:
            Dict of observed metrics (``precision``, ``fp_rate``,
            ``critical_incidents``, …) used to evaluate gates.
        force:
            Skip gate checks (use only for system-internal operations like
            auto-disable from the calibration job).
        tenant_id:
            Tenant context for the audit-log entry.  Defaults to the system
            sentinel UUID.
        canary_partition:
            Fraction of traffic to route through the detector when in CANARY state
            (0.0–1.0).  If not supplied, the policy default is used.

        Returns
        -------
        DetectorState
            The new state (same as *target* on success).

        Raises
        ------
        LifecycleError
            If the transition is illegal or gates are not satisfied.
        """
        state_str, entered_at = await self._store.latest_state(detector, version)
        current = DetectorState(state_str)

        # Check legality of the transition.
        key = (str(current), str(target))
        if key not in LEGAL_TRANSITIONS:
            raise LifecycleError(
                f"Transition {current} -> {target} is not a legal lifecycle transition."
            )

        policy_key = LEGAL_TRANSITIONS[key]

        # Calculate days spent in the current state.
        if entered_at is not None:
            now = datetime.now(tz=UTC)
            entered_aware = entered_at if entered_at.tzinfo is not None else entered_at.replace(tzinfo=UTC)
            days_in_state = (now - entered_aware) / timedelta(days=1)
        else:
            days_in_state = 0.0

        # Evaluate gates (may raise LifecycleError).
        _check_gates(
            policy_key,
            metrics=metrics,
            days_in_state=days_in_state,
            actor_id=actor_id,
            force=force,
        )

        # Resolve canary_partition default from policy.
        if target == DetectorState.CANARY and canary_partition is None:
            canary_partition = _POLICY.get("canary", {}).get("default_partition", 0.05)

        # Persist the lifecycle row.
        await self._store.write(
            detector=detector,
            version=version,
            state=str(target),
            previous_state=str(current),
            rationale=rationale,
            metrics_snapshot=metrics,
            changed_by=actor_id,
            tenant_id=str(tenant_id) if tenant_id else None,
            canary_partition=canary_partition,
        )

        # Append to the hash-chained audit log.
        audit_tenant = tenant_id or self._default_tenant
        await self._audit.append(
            audit_tenant,
            actor_type="user" if actor_id else "system",
            action="detector_lifecycle_transition",
            actor_id=uuid.UUID(actor_id) if actor_id else None,
            target_type="detector",
            target_id=None,
            payload={
                "detector": detector,
                "version": version,
                "previous_state": str(current),
                "new_state": str(target),
                "rationale": rationale,
                "metrics_snapshot": metrics,
            },
        )

        return target


# ---------------------------------------------------------------------------
# Canary routing helper
# ---------------------------------------------------------------------------


def is_canary_selected(
    detector: str,
    run_id: str,
    partition: float,
) -> bool:
    """Return True if this run should be routed through a CANARY detector.

    Uses a stable SHA-256 hash of ``detector:run_id`` so the selection is
    deterministic and reproducible for the same (detector, run_id) pair.

    Parameters
    ----------
    detector:
        Detector name.
    run_id:
        Run UUID string (or any string that identifies the run).
    partition:
        Fraction of traffic to route (0.0–1.0).  E.g. ``0.05`` = 5%.
    """
    from auditor.async_pipeline.sampler import stable_hash

    h = stable_hash(f"{detector}:{run_id}")
    bucket = h % 10_000
    return bucket < int(partition * 10_000)


# ---------------------------------------------------------------------------
# Shadow verdict store
# ---------------------------------------------------------------------------


class ShadowVerdictStore(Protocol):
    """Persist shadow verdicts produced by SHADOW-state detectors."""

    async def write(self, verdict: object, detector_version: str | None = None) -> None:
        """Write a verdict to the shadow store."""


class InMemoryShadowVerdictStore:
    """In-memory shadow verdict store for tests."""

    def __init__(self) -> None:
        self.verdicts: list[dict] = []

    async def write(self, verdict: object, detector_version: str | None = None) -> None:
        self.verdicts.append({"verdict": verdict, "detector_version": detector_version})


class DbShadowVerdictStore:
    """Production shadow verdict store backed by the ``shadow_verdicts`` table."""

    def __init__(self, session_factory: Any) -> None:
        self._sf = session_factory

    async def write(self, verdict: object, detector_version: str | None = None) -> None:
        from auditor.db.models import ShadowVerdict

        sv = ShadowVerdict(
            verdict_id=str(verdict.verdict_id),
            run_id=str(verdict.run_id),
            tenant_id=str(verdict.tenant_id),
            detector=verdict.detector,
            detector_version=detector_version,
            asi_category=verdict.asi_category,
            result=str(verdict.result),
            confidence=verdict.confidence,
            evidence={"items": [e.model_dump(mode="json") for e in verdict.evidence]},
            judge_model=verdict.judge_model,
            judge_prompt_v=verdict.judge_prompt_v,
            rubric_scores=verdict.rubric_scores,
        )
        async with self._sf() as session, session.begin():
            session.add(sv)


__all__ = [
    "LifecycleError",
    "DetectorLifecycle",
    "InMemoryLifecycleStore",
    "DbLifecycleStore",
    "InMemoryShadowVerdictStore",
    "DbShadowVerdictStore",
    "is_canary_selected",
    "LEGAL_TRANSITIONS",
    "ShadowVerdictStore",
    "LifecycleStore",
    "AuditWriter",
    "NullAuditWriter",
]
