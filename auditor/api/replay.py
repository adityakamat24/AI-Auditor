"""Replay helpers (PRD §9.11.3) — standalone functions, no FastAPI router here.

The HITL routes (``auditor/api/hitl_routes.py``) call these functions; this module
intentionally does NOT define a router so the routes agent owns the endpoint surface.

Public API
----------
reconstruct_run(run_id, tenant_id) → Trace
    Thin wrapper over :func:`auditor.events.store.load_trace`.

build_export_bundle(trace, *, secret) → dict
    Portable, JSON-serialisable bundle with an HMAC-SHA256 signature.

verify_export_bundle(bundle, *, secret) → bool
    Verify the HMAC-SHA256 signature of a bundle returned by :func:`build_export_bundle`.

replay_with_judge(trace, *, category, rubric, prompt_version) → JudgeResult
    Re-invoke the judge on the trace at a given prompt version (calibration use-case).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from uuid import UUID

from auditor.detectors.base import Trace
from auditor.events.store import load_trace
from auditor.judge.client import JudgeResult, get_judge
from auditor.logging import get_logger

log = get_logger("auditor.api.replay")


# ---------------------------------------------------------------------------
# Trace reconstruction
# ---------------------------------------------------------------------------


async def reconstruct_run(run_id: UUID, tenant_id: UUID) -> Trace:
    """Load a stored run trace from the event store.

    Parameters
    ----------
    run_id:
        UUID of the run to reconstruct.
    tenant_id:
        Owning tenant; used for row-level security in the DB query.

    Returns
    -------
    Trace
        The materialised trace with all persisted events in chronological order.
    """
    log.info("replay.reconstruct_run", run_id=str(run_id), tenant_id=str(tenant_id))
    return await load_trace(run_id, tenant_id)


# ---------------------------------------------------------------------------
# Export bundle
# ---------------------------------------------------------------------------

_BUNDLE_VERSION = 1


def _canonical_json(obj: object) -> bytes:
    """Deterministic, compact JSON serialisation for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_export_bundle(trace: Trace, *, secret: bytes) -> dict:
    """Build a signed, portable JSON bundle from *trace*.

    The bundle is self-contained and safe to share with external security teams.
    The ``signature`` field is HMAC-SHA256 over the canonical JSON of the bundle
    payload (everything except the ``signature`` key itself).

    Parameters
    ----------
    trace:
        The run trace to export.
    secret:
        HMAC secret key (bytes). Use ``Settings.jwt_secret.encode()`` for the
        process-wide key.

    Returns
    -------
    dict
        JSON-serialisable bundle with keys: ``version``, ``run_id``, ``tenant_id``,
        ``declared_goal``, ``events``, ``metadata``, ``signature``.
    """
    events_as_dicts = [_event_to_dict(e) for e in trace.events]

    payload: dict = {
        "version": _BUNDLE_VERSION,
        "run_id": str(trace.run_id),
        "tenant_id": str(trace.tenant_id),
        "declared_goal": trace.declared_goal,
        "events": events_as_dicts,
        "metadata": trace.metadata,
    }

    sig = _hmac_sign(payload, secret)
    return {**payload, "signature": sig}


def verify_export_bundle(bundle: dict, *, secret: bytes) -> bool:
    """Verify the HMAC-SHA256 signature on a bundle built by :func:`build_export_bundle`.

    Returns *True* when the signature is valid, *False* otherwise (including when the
    ``signature`` key is missing or the bundle has been tampered with).
    """
    sig = bundle.get("signature")
    if not sig:
        return False

    payload = {k: v for k, v in bundle.items() if k != "signature"}
    expected = _hmac_sign(payload, secret)
    # constant-time comparison to prevent timing attacks
    return hmac.compare_digest(sig, expected)


# ---------------------------------------------------------------------------
# Replay with judge (calibration)
# ---------------------------------------------------------------------------


async def replay_with_judge(
    trace: Trace,
    *,
    category: str,
    rubric: str,
    prompt_version: int = 1,
) -> JudgeResult:
    """Re-invoke the LLM judge on *trace* at a specified prompt version.

    Useful for calibration: re-score historical traces against an updated rubric or
    prompt without re-running the full agent. The judge is selected via
    :func:`~auditor.judge.client.get_judge` (live when an Anthropic key is configured,
    offline stub otherwise).

    Parameters
    ----------
    trace:
        The run trace to evaluate.
    category:
        ASI category string (e.g. ``"ASI01"``).
    rubric:
        Rubric prompt text for the judge.
    prompt_version:
        Prompt version integer; recorded in the returned :class:`JudgeResult`.

    Returns
    -------
    JudgeResult
        The judge's structured verdict.
    """
    judge = get_judge()
    trace_slice = _trace_to_slice(trace)

    log.info(
        "replay.judge",
        run_id=str(trace.run_id),
        category=category,
        prompt_version=prompt_version,
    )

    return await judge.judge(
        category=category,
        rubric=rubric,
        trace_slice=trace_slice,
        prompt_version=prompt_version,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _event_to_dict(event: object) -> dict:
    """Convert a Pydantic event model to a plain dict (JSON-safe)."""
    try:
        # Pydantic v2
        return json.loads(event.model_dump_json())  # type: ignore[union-attr]
    except AttributeError:
        # Fallback: use dict() for non-Pydantic objects
        return dict(event)  # type: ignore[call-overload]


def _trace_to_slice(trace: Trace) -> str:
    """Serialise the trace to a compact text slice for the judge prompt."""
    lines: list[str] = [
        f"run_id={trace.run_id}",
        f"tenant_id={trace.tenant_id}",
        f"declared_goal={trace.declared_goal!r}",
        "events:",
    ]
    # Fields to exclude from the human-readable slice (large binary / redundant IDs).
    _SKIP = {"event_id", "run_id", "tenant_id", "span_id", "parent_span_id",
             "schema_version", "channel", "pid"}
    for ev in trace.events:
        ev_dict = _event_to_dict(ev)
        event_type = ev_dict.get("event_type", "?")
        ts = ev_dict.get("ts", "?")
        payload_parts = [
            f"{k}={v!r}"
            for k, v in ev_dict.items()
            if k not in _SKIP and k not in ("event_type", "ts") and v is not None
        ]
        detail = " ".join(payload_parts)
        lines.append(f"  {event_type} ts={ts} {detail}")
    return "\n".join(lines)


def _hmac_sign(payload: dict, secret: bytes) -> str:
    """Return hex-encoded HMAC-SHA256 of the canonical JSON of *payload*."""
    msg = _canonical_json(payload)
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


__all__ = [
    "reconstruct_run",
    "build_export_bundle",
    "verify_export_bundle",
    "replay_with_judge",
]
