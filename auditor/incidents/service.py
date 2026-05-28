"""Incident service layer (PRD §9.10.5).

Provides:
  - ``open_incident_for_flag`` - creates an Incident for a High/Critical flag.
  - ``add_comment`` / ``add_action_item`` - helper writers.
  - ``find_similar`` - deterministic cross-incident correlation (no embeddings).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from auditor.db.models import Incident, IncidentActionItem, IncidentComment
from auditor.ids import uuid7

# Severities that automatically open an incident.
_INCIDENT_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})

# Scoring weights for cross-incident correlation.
_WEIGHT_DETECTOR = 3
_WEIGHT_ASI_CATEGORY = 2
_WEIGHT_AGENT_ROLE = 1
_WEIGHT_TOOL = 2


# ------------------------------------------------------------------------------- public: open incident


def open_incident_for_flag(flag: Any) -> Incident | None:
    """Create and return a new ``Incident`` ORM object for *flag*.

    Returns ``None`` for low/medium severity flags (no incident opened).
    The returned object is NOT yet added to a session - callers do ``session.add(incident)``
    after any additional setup (e.g. paging for critical incidents).

    Args:
        flag: A ``Flag`` ORM object or compatible duck-typed object with at least
              ``flag_id``, ``tenant_id``, ``severity``, and ``asi_categories`` attributes.
    """
    severity = (getattr(flag, "severity", "") or "").lower()
    if severity not in _INCIDENT_SEVERITIES:
        return None

    incident = Incident(
        incident_id=str(uuid7()),
        tenant_id=str(flag.tenant_id),
        primary_flag_id=str(flag.flag_id),
        related_flag_ids=[],
        severity=severity,
        state="OPEN",
        assignee_id=None,
        opened_at=datetime.now(tz=UTC),
        triaged_at=None,
        contained_at=None,
        resolved_at=None,
        post_mortem_uri=None,
        dismissal_rationale=None,
    )

    # Critical flags should also trigger paging (signal surfaced in the metadata dict
    # attached to the incident so the caller / notifier can act on it).
    if severity == "critical":
        # In a full implementation, a PagerDuty/Slack notifier would read this.
        # We expose it as a flag attribute on the object so tests can assert it.
        incident._should_page = True  # type: ignore[attr-defined]  # noqa: SLF001

    return incident


# ------------------------------------------------------------------------------- public: comment


def build_comment(
    *,
    incident_id: str,
    author_id: str,
    body: str,
) -> IncidentComment:
    """Build (but do not persist) an ``IncidentComment`` for *incident_id*."""
    return IncidentComment(
        comment_id=str(uuid7()),
        incident_id=incident_id,
        author_id=author_id,
        body=body,
        ts=datetime.now(tz=UTC),
    )


# ------------------------------------------------------------------------------- public: action item


def build_action_item(
    *,
    incident_id: str,
    owner_id: str | None,
    description: str,
    due_date: Any = None,
) -> IncidentActionItem:
    """Build (but do not persist) an ``IncidentActionItem``."""
    return IncidentActionItem(
        action_id=str(uuid7()),
        incident_id=incident_id,
        owner_id=owner_id,
        description=description,
        status="open",
        due_date=due_date,
        created_at=datetime.now(tz=UTC),
        completed_at=None,
    )


# ------------------------------------------------------------------------------- public: correlation


def find_similar(incident: Any, recent: list[Any]) -> list[tuple[Any, int]]:
    """Return *recent* incidents ranked by similarity to *incident*.

    Similarity is a deterministic score over four axes - no embeddings, no ML:

    * detector match      → +3 points  (strongest signal: same detector fired)
    * ASI category overlap → +2 per shared category  (weighted by count)
    * agent role match    → +1 point  (same agent type involved)
    * involved tool match → +2 per shared tool  (strong structural signal)

    Returns:
        List of ``(incident_obj, score)`` tuples sorted descending by score,
        with zero-score incidents excluded.

    Args:
        incident: The reference incident.  Expected attributes (all optional - falls
                  back gracefully to empty): ``primary_flag_id``, ``_detector``,
                  ``_asi_categories``, ``_agent_role``, ``_tools``.
        recent: Candidate incidents to compare against (from the last 30 days, say).
    """
    ref_detector = _attr(incident, "_detector", "")
    ref_categories: set[str] = set(_attr(incident, "_asi_categories", []) or [])
    ref_role = _attr(incident, "_agent_role", "")
    ref_tools: set[str] = set(_attr(incident, "_tools", []) or [])

    scored: list[tuple[Any, int]] = []
    for candidate in recent:
        if _same_id(candidate, incident):
            continue
        score = 0

        # Detector match.
        if ref_detector and _attr(candidate, "_detector", "") == ref_detector:
            score += _WEIGHT_DETECTOR

        # ASI category overlap.
        cand_categories: set[str] = set(_attr(candidate, "_asi_categories", []) or [])
        overlap = ref_categories & cand_categories
        score += len(overlap) * _WEIGHT_ASI_CATEGORY

        # Agent role.
        if ref_role and _attr(candidate, "_agent_role", "") == ref_role:
            score += _WEIGHT_AGENT_ROLE

        # Tool overlap.
        cand_tools: set[str] = set(_attr(candidate, "_tools", []) or [])
        tool_overlap = ref_tools & cand_tools
        score += len(tool_overlap) * _WEIGHT_TOOL

        if score > 0:
            scored.append((candidate, score))

    scored.sort(key=lambda t: t[1], reverse=True)
    return scored


# ------------------------------------------------------------------------------- private helpers


def _attr(obj: Any, name: str, default: Any) -> Any:
    return getattr(obj, name, default)


def _same_id(a: Any, b: Any) -> bool:
    """Return True if *a* and *b* have the same ``incident_id``."""
    return str(getattr(a, "incident_id", "")) == str(getattr(b, "incident_id", ""))


# ------------------------------------------------------------------------------- public: service class


class IncidentService:
    """Thin service wrapper providing stateful helpers.

    Intended for use inside route handlers that already have a DB session.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    async def open_for_flag(self, flag: Any) -> Incident | None:
        """Open an incident for *flag* and add it to the session (if applicable)."""
        incident = open_incident_for_flag(flag)
        if incident is not None:
            self._session.add(incident)
        return incident

    async def add_comment(self, *, incident_id: str, author_id: str, body: str) -> IncidentComment:
        comment = build_comment(incident_id=incident_id, author_id=author_id, body=body)
        self._session.add(comment)
        return comment

    async def add_action_item(
        self,
        *,
        incident_id: str,
        owner_id: str | None,
        description: str,
        due_date: Any = None,
    ) -> IncidentActionItem:
        item = build_action_item(
            incident_id=incident_id,
            owner_id=owner_id,
            description=description,
            due_date=due_date,
        )
        self._session.add(item)
        return item


__all__ = [
    "open_incident_for_flag",
    "build_comment",
    "build_action_item",
    "find_similar",
    "IncidentService",
]
