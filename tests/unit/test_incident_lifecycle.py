"""Unit tests for auditor.incidents.lifecycle and auditor.incidents.service.

No DB required — all objects are simple in-memory mock objects.

Coverage:
  - Full happy path: OPEN→TRIAGING→INVESTIGATING→CONTAINED→RESOLVED→POST_MORTEM_COMPLETE
  - Illegal state jumps raise IncidentTransitionError.
  - Reviewer cannot reach RESOLVED (admin can).
  - POST_MORTEM_COMPLETE on critical without post_mortem_uri raises; with it succeeds.
  - DISMISSED requires rationale.
  - open_incident_for_flag creates OPEN for critical/high, returns None for low/medium.
  - find_similar ranks incidents sharing detector+category+tool above unrelated ones.
"""

from __future__ import annotations

import pytest
from auditor.incidents.lifecycle import (
    ALL_STATES,
    LEGAL_TRANSITIONS,
    IncidentStateMachine,
    IncidentTransitionError,
)
from auditor.incidents.service import find_similar, open_incident_for_flag

# ------------------------------------------------------------------------------- helpers


def _make_incident(
    state: str = "OPEN",
    severity: str = "high",
    *,
    incident_id: str = "inc-1",
    detector: str = "",
    asi_categories: list[str] | None = None,
    agent_role: str = "",
    tools: list[str] | None = None,
) -> object:
    """Return a minimal mock Incident compatible with IncidentStateMachine."""

    class MockIncident:
        pass

    inc = MockIncident()
    inc.incident_id = incident_id
    inc.state = state
    inc.severity = severity
    inc.triaged_at = None
    inc.contained_at = None
    inc.resolved_at = None
    inc.post_mortem_uri = None
    inc.dismissal_rationale = None
    # Correlation metadata (used by find_similar).
    inc._detector = detector
    inc._asi_categories = asi_categories or []
    inc._agent_role = agent_role
    inc._tools = tools or []
    return inc


def _make_flag(severity: str = "high") -> object:
    class MockFlag:
        pass

    f = MockFlag()
    f.flag_id = "flag-1"
    f.tenant_id = "tenant-1"
    f.severity = severity
    f.asi_categories = ["ASI01"]
    return f


# ------------------------------------------------------------------------------- state machine: happy paths


class TestHappyPath:
    def test_full_lifecycle(self):
        """OPEN→TRIAGING→INVESTIGATING→CONTAINED→RESOLVED→POST_MORTEM_COMPLETE."""
        inc = _make_incident(state="OPEN", severity="high")
        sm = IncidentStateMachine()

        sm.transition(inc, "TRIAGING", actor_role="reviewer")
        assert inc.state == "TRIAGING"
        assert inc.triaged_at is not None

        sm.transition(inc, "INVESTIGATING", actor_role="reviewer")
        assert inc.state == "INVESTIGATING"

        sm.transition(inc, "CONTAINED", actor_role="reviewer")
        assert inc.state == "CONTAINED"
        assert inc.contained_at is not None

        sm.transition(inc, "RESOLVED", actor_role="admin")
        assert inc.state == "RESOLVED"
        assert inc.resolved_at is not None

        sm.transition(inc, "POST_MORTEM_COMPLETE", actor_role="admin", post_mortem_uri="s3://bucket/pm.md")
        assert inc.state == "POST_MORTEM_COMPLETE"
        assert inc.post_mortem_uri == "s3://bucket/pm.md"

    def test_dismissed_with_rationale(self):
        inc = _make_incident(state="OPEN")
        sm = IncidentStateMachine()
        sm.transition(inc, "DISMISSED", actor_role="reviewer", rationale="False positive — noisy rule")
        assert inc.state == "DISMISSED"
        assert inc.dismissal_rationale == "False positive — noisy rule"

    def test_admin_can_resolve(self):
        inc = _make_incident(state="CONTAINED")
        sm = IncidentStateMachine()
        sm.transition(inc, "RESOLVED", actor_role="admin")
        assert inc.state == "RESOLVED"

    def test_admin_can_dismiss(self):
        inc = _make_incident(state="OPEN")
        sm = IncidentStateMachine()
        sm.transition(inc, "DISMISSED", actor_role="admin", rationale="admin confirmed fp")
        assert inc.state == "DISMISSED"

    def test_post_mortem_non_critical_no_uri_ok(self):
        """Non-critical incidents do NOT require a post_mortem_uri."""
        inc = _make_incident(state="RESOLVED", severity="high")
        sm = IncidentStateMachine()
        sm.transition(inc, "POST_MORTEM_COMPLETE", actor_role="admin")
        assert inc.state == "POST_MORTEM_COMPLETE"


# ------------------------------------------------------------------------------- state machine: illegal transitions


class TestIllegalTransitions:
    def test_jump_from_open_to_contained_raises(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError, match="Cannot transition from 'OPEN' to 'CONTAINED'"):
            IncidentStateMachine().transition(inc, "CONTAINED", actor_role="admin")

    def test_jump_from_open_to_resolved_raises(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "RESOLVED", actor_role="admin")

    def test_jump_from_triaging_to_resolved_raises(self):
        inc = _make_incident(state="TRIAGING")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "RESOLVED", actor_role="admin")

    def test_terminal_post_mortem_complete_raises(self):
        inc = _make_incident(state="POST_MORTEM_COMPLETE")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "RESOLVED", actor_role="admin")

    def test_terminal_dismissed_raises(self):
        inc = _make_incident(state="DISMISSED")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "TRIAGING", actor_role="admin")

    def test_unknown_target_raises(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError, match="Unknown state"):
            IncidentStateMachine().transition(inc, "BANANA", actor_role="admin")

    def test_backward_transition_raises(self):
        inc = _make_incident(state="INVESTIGATING")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "TRIAGING", actor_role="admin")


# ------------------------------------------------------------------------------- RBAC enforcement


class TestRBAC:
    def test_reviewer_blocked_from_resolved(self):
        inc = _make_incident(state="CONTAINED")
        with pytest.raises(IncidentTransitionError, match="not authorised"):
            IncidentStateMachine().transition(inc, "RESOLVED", actor_role="reviewer")

    def test_reviewer_blocked_from_post_mortem_complete(self):
        inc = _make_incident(state="RESOLVED")
        with pytest.raises(IncidentTransitionError, match="not authorised"):
            IncidentStateMachine().transition(
                inc, "POST_MORTEM_COMPLETE", actor_role="reviewer", post_mortem_uri="s3://x"
            )

    def test_admin_allowed_resolved(self):
        inc = _make_incident(state="CONTAINED")
        IncidentStateMachine().transition(inc, "RESOLVED", actor_role="admin")
        assert inc.state == "RESOLVED"

    def test_readonly_blocked_from_triaging(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError):
            IncidentStateMachine().transition(inc, "TRIAGING", actor_role="readonly")

    def test_reviewer_can_triage(self):
        inc = _make_incident(state="OPEN")
        IncidentStateMachine().transition(inc, "TRIAGING", actor_role="reviewer")
        assert inc.state == "TRIAGING"

    def test_reviewer_can_investigate(self):
        inc = _make_incident(state="TRIAGING")
        IncidentStateMachine().transition(inc, "INVESTIGATING", actor_role="reviewer")
        assert inc.state == "INVESTIGATING"

    def test_reviewer_can_contain(self):
        inc = _make_incident(state="INVESTIGATING")
        IncidentStateMachine().transition(inc, "CONTAINED", actor_role="reviewer")
        assert inc.state == "CONTAINED"


# ------------------------------------------------------------------------------- post-mortem gate


class TestPostMortemGate:
    def test_critical_without_uri_raises(self):
        inc = _make_incident(state="RESOLVED", severity="critical")
        with pytest.raises(IncidentTransitionError, match="post_mortem_uri"):
            IncidentStateMachine().transition(inc, "POST_MORTEM_COMPLETE", actor_role="admin")

    def test_critical_with_empty_uri_raises(self):
        inc = _make_incident(state="RESOLVED", severity="critical")
        with pytest.raises(IncidentTransitionError, match="post_mortem_uri"):
            IncidentStateMachine().transition(
                inc, "POST_MORTEM_COMPLETE", actor_role="admin", post_mortem_uri="   "
            )

    def test_critical_with_uri_succeeds(self):
        inc = _make_incident(state="RESOLVED", severity="critical")
        IncidentStateMachine().transition(
            inc, "POST_MORTEM_COMPLETE", actor_role="admin", post_mortem_uri="s3://bucket/postmortem.md"
        )
        assert inc.state == "POST_MORTEM_COMPLETE"
        assert inc.post_mortem_uri == "s3://bucket/postmortem.md"

    def test_high_without_uri_succeeds(self):
        """Non-critical incidents do not require a URI."""
        inc = _make_incident(state="RESOLVED", severity="high")
        IncidentStateMachine().transition(inc, "POST_MORTEM_COMPLETE", actor_role="admin")
        assert inc.state == "POST_MORTEM_COMPLETE"


# ------------------------------------------------------------------------------- DISMISSED gate


class TestDismissedGate:
    def test_dismissed_without_rationale_raises(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError, match="rationale"):
            IncidentStateMachine().transition(inc, "DISMISSED", actor_role="reviewer")

    def test_dismissed_empty_rationale_raises(self):
        inc = _make_incident(state="OPEN")
        with pytest.raises(IncidentTransitionError, match="rationale"):
            IncidentStateMachine().transition(inc, "DISMISSED", actor_role="reviewer", rationale="   ")

    def test_dismissed_with_rationale_succeeds(self):
        inc = _make_incident(state="OPEN")
        IncidentStateMachine().transition(inc, "DISMISSED", actor_role="reviewer", rationale="fp")
        assert inc.state == "DISMISSED"


# ------------------------------------------------------------------------------- open_incident_for_flag


class TestOpenIncidentForFlag:
    def test_critical_opens_incident(self):
        flag = _make_flag(severity="critical")
        inc = open_incident_for_flag(flag)
        assert inc is not None
        assert inc.state == "OPEN"
        assert inc.severity == "critical"

    def test_high_opens_incident(self):
        flag = _make_flag(severity="high")
        inc = open_incident_for_flag(flag)
        assert inc is not None
        assert inc.state == "OPEN"
        assert inc.severity == "high"

    def test_medium_returns_none(self):
        flag = _make_flag(severity="medium")
        assert open_incident_for_flag(flag) is None

    def test_low_returns_none(self):
        flag = _make_flag(severity="low")
        assert open_incident_for_flag(flag) is None

    def test_critical_sets_should_page(self):
        """Critical flag incidents are flagged for paging."""
        flag = _make_flag(severity="critical")
        inc = open_incident_for_flag(flag)
        assert getattr(inc, "_should_page", False) is True

    def test_high_does_not_page(self):
        flag = _make_flag(severity="high")
        inc = open_incident_for_flag(flag)
        assert getattr(inc, "_should_page", False) is False

    def test_incident_links_to_flag(self):
        flag = _make_flag(severity="high")
        inc = open_incident_for_flag(flag)
        assert str(inc.primary_flag_id) == str(flag.flag_id)
        assert str(inc.tenant_id) == str(flag.tenant_id)


# ------------------------------------------------------------------------------- find_similar


class TestFindSimilar:
    def _related(self) -> object:
        """Incident sharing detector, category, and tool with reference."""
        return _make_incident(
            incident_id="inc-related",
            detector="asi01_detector",
            asi_categories=["ASI01"],
            tools=["exec_shell"],
        )

    def _unrelated(self) -> object:
        """Incident with no overlap at all."""
        return _make_incident(
            incident_id="inc-unrelated",
            detector="asi05_detector",
            asi_categories=["ASI05"],
            tools=["file_read"],
        )

    def _ref(self) -> object:
        return _make_incident(
            incident_id="inc-ref",
            detector="asi01_detector",
            asi_categories=["ASI01"],
            tools=["exec_shell"],
        )

    def test_related_ranks_above_unrelated(self):
        ref = self._ref()
        related = self._related()
        unrelated = self._unrelated()
        results = find_similar(ref, [related, unrelated])
        ids = [str(inc.incident_id) for inc, _ in results]
        assert ids[0] == "inc-related"

    def test_unrelated_excluded_when_zero_score(self):
        ref = self._ref()
        unrelated = self._unrelated()
        results = find_similar(ref, [unrelated])
        # unrelated shares nothing with ref
        assert results == []

    def test_self_excluded(self):
        ref = self._ref()
        results = find_similar(ref, [ref])
        assert results == []

    def test_partial_overlap_has_nonzero_score(self):
        ref = self._ref()
        partial = _make_incident(
            incident_id="inc-partial",
            detector="",           # no detector match
            asi_categories=["ASI01"],  # category match → +2
            tools=[],
        )
        results = find_similar(ref, [partial])
        assert len(results) == 1
        assert results[0][1] == 2

    def test_empty_recent_returns_empty(self):
        ref = self._ref()
        assert find_similar(ref, []) == []

    def test_scores_are_sorted_descending(self):
        ref = self._ref()
        high = _make_incident(
            incident_id="inc-high",
            detector="asi01_detector",
            asi_categories=["ASI01"],
            tools=["exec_shell"],
        )
        medium = _make_incident(
            incident_id="inc-medium",
            detector="asi01_detector",
            asi_categories=[],
            tools=[],
        )
        results = find_similar(ref, [medium, high])
        assert results[0][0].incident_id == "inc-high"
        assert results[0][1] > results[1][1]


# ------------------------------------------------------------------------------- legal transitions coverage


class TestLegalTransitionsStructure:
    def test_all_non_terminal_states_have_outbound(self):
        terminal = {"POST_MORTEM_COMPLETE", "DISMISSED"}
        for state in ALL_STATES - terminal:
            assert LEGAL_TRANSITIONS[state], f"State {state} has no outbound transitions"

    def test_terminal_states_have_no_outbound(self):
        for state in ("POST_MORTEM_COMPLETE", "DISMISSED"):
            assert LEGAL_TRANSITIONS[state] == frozenset()
