"""Incident state machine (PRD §9.10.5).

Enforces legal state transitions and RBAC rules for the incident lifecycle.
All transition logic lives here; the API layer delegates to this module.

State graph:
    OPEN ──► TRIAGING ──► INVESTIGATING ──► CONTAINED ──► RESOLVED ──► POST_MORTEM_COMPLETE
       │
       └──► DISMISSED (false positive, requires rationale)

RBAC:
  - reviewer: OPEN→TRIAGING, TRIAGING→INVESTIGATING, INVESTIGATING→CONTAINED,
               OPEN→DISMISSED (with rationale), add comments.
  - admin: all reviewer actions + CONTAINED→RESOLVED, RESOLVED→POST_MORTEM_COMPLETE,
            reassign incidents.
  - readonly: view only (no transitions).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# ------------------------------------------------------------------------------- constants

# All valid incident states (must match DB CHECK constraint).
ALL_STATES: frozenset[str] = frozenset(
    {
        "OPEN",
        "TRIAGING",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "POST_MORTEM_COMPLETE",
        "DISMISSED",
    }
)

# Ordered chain of primary lifecycle transitions (any role with sufficient RBAC).
# Maps source_state → set of allowed target states.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"TRIAGING", "DISMISSED"}),
    "TRIAGING": frozenset({"INVESTIGATING"}),
    "INVESTIGATING": frozenset({"CONTAINED"}),
    "CONTAINED": frozenset({"RESOLVED"}),
    "RESOLVED": frozenset({"POST_MORTEM_COMPLETE"}),
    # Terminal states — no outbound transitions.
    "POST_MORTEM_COMPLETE": frozenset(),
    "DISMISSED": frozenset(),
}

# Which roles may perform each *target* state transition.
# reviewer: OPEN→TRIAGING, TRIAGING→INVESTIGATING, INVESTIGATING→CONTAINED, OPEN→DISMISSED
# admin: all of the above + CONTAINED→RESOLVED, RESOLVED→POST_MORTEM_COMPLETE
_REVIEWER_TARGETS: frozenset[str] = frozenset({"TRIAGING", "INVESTIGATING", "CONTAINED", "DISMISSED"})
_ADMIN_ONLY_TARGETS: frozenset[str] = frozenset({"RESOLVED", "POST_MORTEM_COMPLETE"})


# ------------------------------------------------------------------------------- exception


class IncidentTransitionError(ValueError):
    """Raised when a requested state transition is illegal or the actor lacks permission."""


# ------------------------------------------------------------------------------- state machine


class IncidentStateMachine:
    """Validates and applies state transitions for an incident.

    Usage::

        sm = IncidentStateMachine()
        sm.transition(incident, "TRIAGING", actor_role="reviewer")
        # incident.state is now "TRIAGING", incident.triaged_at is set.
    """

    # ---------------------------------------------------------------------- public API

    def transition(
        self,
        incident: Any,
        target: str,
        *,
        actor_role: str,
        post_mortem_uri: str | None = None,
        rationale: str | None = None,
    ) -> None:
        """Apply a state transition to *incident* in-place.

        Args:
            incident: An ORM ``Incident`` object (or compatible duck-typed object with
                      ``state``, ``severity``, and the timestamp columns).
            target: The desired target state (must be in ``ALL_STATES``).
            actor_role: The requesting user's role (``"admin"``, ``"reviewer"``,
                        ``"readonly"``).
            post_mortem_uri: Required for RESOLVED→POST_MORTEM_COMPLETE on a *critical*
                             incident.
            rationale: Required for OPEN→DISMISSED.

        Raises:
            IncidentTransitionError: If the transition is illegal, the actor lacks RBAC
                permission, or a required field is missing.
        """
        self._validate_target_state(target)
        self._validate_legal(incident.state, target)
        self._validate_rbac(target, actor_role)

        # Business-logic gates:
        if target == "DISMISSED":
            self._require_rationale(rationale, target)
        if target == "POST_MORTEM_COMPLETE":
            self._check_post_mortem_gate(incident, post_mortem_uri)

        # Apply the transition.
        self._apply(incident, target, rationale=rationale, post_mortem_uri=post_mortem_uri)

    def can_transition(self, actor_role: str, target: str) -> bool:
        """Return True if *actor_role* is allowed to move an incident to *target*."""
        if target in _REVIEWER_TARGETS:
            return actor_role in {"reviewer", "admin"}
        if target in _ADMIN_ONLY_TARGETS:
            return actor_role == "admin"
        return False

    # ---------------------------------------------------------------------- private helpers

    @staticmethod
    def _validate_target_state(target: str) -> None:
        if target not in ALL_STATES:
            raise IncidentTransitionError(
                f"Unknown state '{target}'. Valid states: {sorted(ALL_STATES)}"
            )

    @staticmethod
    def _validate_legal(current: str, target: str) -> None:
        allowed = LEGAL_TRANSITIONS.get(current, frozenset())
        if target not in allowed:
            raise IncidentTransitionError(
                f"Cannot transition from '{current}' to '{target}'. "
                f"Legal targets from '{current}': {sorted(allowed) or '(none — terminal state)'}"
            )

    @staticmethod
    def _validate_rbac(target: str, actor_role: str) -> None:
        if actor_role == "admin":
            return  # admins may do anything
        if actor_role == "reviewer" and target in _REVIEWER_TARGETS:
            return
        if actor_role == "readonly":
            raise IncidentTransitionError(
                "Role 'readonly' cannot perform any incident transitions."
            )
        raise IncidentTransitionError(
            f"Role '{actor_role}' is not authorised to transition an incident to '{target}'. "
            f"Required role: 'admin'."
        )

    @staticmethod
    def _require_rationale(rationale: str | None, target: str) -> None:
        if not rationale or not rationale.strip():
            raise IncidentTransitionError(
                f"A non-empty rationale is required to transition to '{target}'."
            )

    @staticmethod
    def _check_post_mortem_gate(incident: Any, post_mortem_uri: str | None) -> None:
        """For critical incidents, POST_MORTEM_COMPLETE requires a non-empty post_mortem_uri."""
        severity = (getattr(incident, "severity", "") or "").lower()
        if severity == "critical":
            if not post_mortem_uri or not post_mortem_uri.strip():
                raise IncidentTransitionError(
                    "POST_MORTEM_COMPLETE on a 'critical' incident requires a non-empty "
                    "'post_mortem_uri'. Provide the URI of the post-mortem document."
                )

    @staticmethod
    def _apply(
        incident: Any,
        target: str,
        *,
        rationale: str | None,
        post_mortem_uri: str | None,
    ) -> None:
        """Mutate *incident* fields for the new state."""
        now = datetime.now(tz=UTC)
        incident.state = target

        if target == "TRIAGING":
            incident.triaged_at = now
        elif target == "CONTAINED":
            incident.contained_at = now
        elif target == "RESOLVED":
            incident.resolved_at = now
        elif target == "DISMISSED":
            incident.dismissal_rationale = rationale
        elif target == "POST_MORTEM_COMPLETE" and post_mortem_uri:
            incident.post_mortem_uri = post_mortem_uri


__all__ = [
    "ALL_STATES",
    "LEGAL_TRANSITIONS",
    "IncidentTransitionError",
    "IncidentStateMachine",
]
