"""Agent control-plane API: dispatch a real agent run from the UI and watch the audit unfold.

This is the *interactive* surface the demo needs:

- ``POST /agent/runs`` — a reviewer/admin submits ``{task}`` from the UI; the auditor mints an mTLS
  cert, spawns the harness subprocess in agent mode (real Claude via LiteLLM), and returns the new
  ``run_id``. The harness streams telemetry events back over mTLS as usual; when it disconnects, the
  existing IPC ``on_disconnect`` schedules the post-run audit (sampler → detectors → live judge → flag).
- ``GET /agent/runs/{run_id}`` — the UI polls this to render the run as it happens: harness
  process status, events as they arrive, sampler decision, verdicts grouped by the four operator
  checks, the aggregated flag, and the auto-opened incident.

This launches subprocesses from the API, which is fine for the demo / single-host dev environment;
a production deployment would route this to a dedicated harness-launcher service.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import require_role
from auditor.api.hitl_routes import get_db_session
from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.config import get_settings
from auditor.db.models import Event, Flag, Incident, Run, SamplerDecision, Verdict
from auditor.ids import uuid7
from auditor.verdicts.checks import CHECK_TITLES, Check, check_for_detector

agent_router = APIRouter(prefix="/agent", tags=["agent"])

# Default tenant for demo runs when the caller's JWT has no tenant_id.
DEMO_TENANT = UUID("00000000-0000-0000-0000-000000000001")

# Per-process registry of harness subprocesses (run_id → info). Survives until the auditor restarts.
_RUNS: dict[str, dict] = {}
_RUN_LOG_DIR = Path(".run/agent_runs")


class AgentRunRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4000)
    max_turns: int = Field(default=12, ge=1, le=30)


def _spawn_harness(task: str, max_turns: int, tenant_id: UUID) -> dict:
    """Mint a per-run mTLS cert, spawn the harness in agent mode, return the run info. Blocking — call
    via :func:`asyncio.to_thread` from async handlers."""
    settings = get_settings()
    init_ca(settings.data_dir)
    _RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid7())
    cert, key, ca = mint_leaf_to_files(
        settings.data_dir, role="harness", run_id=run_id,
        tenant_id=str(tenant_id), hostname="harness.local",
    )

    env = dict(os.environ)
    env.update({
        "HARNESS_MODE": "agent",
        "HARNESS_TASK": task,
        "HARNESS_MAX_TURNS": str(max_turns),
        "HARNESS_CERT": str(cert),
        "HARNESS_KEY": str(key),
        "HARNESS_CA": str(ca),
        "HARNESS_RUN_ID": run_id,
        "HARNESS_TENANT_ID": str(tenant_id),
        "IPC_MTLS_ENABLED": "true",
        "GATE_TIMEOUT_MS": "500",
    })

    log_path = _RUN_LOG_DIR / f"{run_id}.log"
    log_handle = log_path.open("w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(  # noqa: S603 - controlled command (sys.executable + a fixed module name)
        [sys.executable, "-m", "harness.main"],
        env=env, stdout=log_handle, stderr=subprocess.STDOUT, cwd=os.getcwd(),
    )
    info = {
        "run_id": run_id, "tenant_id": str(tenant_id), "task": task,
        "pid": proc.pid, "started_at": datetime.now(tz=UTC).isoformat(),
        "log_path": str(log_path), "_proc": proc, "_log_handle": log_handle,
    }
    _RUNS[run_id] = info
    return info


def _harness_status(run_id: str) -> str:
    """`running` while the subprocess is alive; `completed` on clean exit; `exited(N)` on non-zero."""
    info = _RUNS.get(run_id)
    if info is None:
        return "unknown"
    code = info["_proc"].poll()
    if code is None:
        return "running"
    return "completed" if code == 0 else f"exited({code})"


@agent_router.post("/runs", status_code=status.HTTP_201_CREATED)
async def start_agent_run(
    body: AgentRunRequest,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
) -> dict:
    """Launch a new agent run on the user-supplied task; returns the new ``run_id`` immediately."""
    tenant_id = UUID(claims.get("tenant_id") or str(DEMO_TENANT))
    info = await asyncio.to_thread(_spawn_harness, body.task, body.max_turns, tenant_id)
    return {
        "run_id": info["run_id"],
        "tenant_id": info["tenant_id"],
        "task": info["task"],
        "started_at": info["started_at"],
    }


@agent_router.get("/runs/{run_id}")
async def get_agent_run(
    run_id: str,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Live view of the run for the UI to render: events, sampler decision, verdicts, flag, incident."""
    try:
        run_uuid = UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid run_id") from exc

    run = await session.get(Run, run_uuid)
    if run is None and run_id not in _RUNS:
        raise HTTPException(status_code=404, detail="run not found")

    events = (await session.execute(
        select(Event).where(Event.run_id == run_uuid).order_by(Event.ts.asc()).limit(500),
    )).scalars().all()
    sampler = (await session.execute(
        select(SamplerDecision).where(SamplerDecision.run_id == run_uuid),
    )).scalars().first()
    flag = (await session.execute(select(Flag).where(Flag.run_id == run_uuid))).scalars().first()
    verdicts = (await session.execute(select(Verdict).where(Verdict.run_id == run_uuid))).scalars().all()
    incident = None
    if flag is not None:
        incident = (await session.execute(
            select(Incident).where(Incident.primary_flag_id == str(flag.flag_id)),
        )).scalars().first()

    # Group non-OK verdicts under the four operator checks (the product's headline lens).
    grouped: dict[Check, dict] = {}
    for verdict in verdicts:
        if verdict.result == "OK":
            continue
        check = check_for_detector(verdict.detector, verdict.asi_category)
        if check is None:
            continue
        bucket = grouped.setdefault(check, {"title": CHECK_TITLES[check], "verdicts": []})
        reason = (verdict.evidence[0].get("reason", "") if verdict.evidence else "")[:400]
        bucket["verdicts"].append({
            "detector": verdict.detector,
            "asi_category": verdict.asi_category,
            "result": verdict.result,
            "confidence": float(verdict.confidence or 0),
            "reason": reason,
        })

    # `audited` flips true when the FULL audit pipeline is done — sampler said NONE (skipped) or the
    # orchestrator finished persisting verdicts. The sampler row is written first, but the orchestrator
    # (live judge calls) takes a few more seconds; polling clients should wait for this flag.
    audit_complete = sampler is not None and (sampler.tier_fired == "NONE" or len(verdicts) > 0)
    return {
        "run_id": run_id,
        "harness_status": _harness_status(run_id),
        "audited": audit_complete,
        "run": ({
            "status": run.status,
            "declared_goal": run.declared_goal,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        } if run else None),
        "sampler": ({
            "tier": sampler.tier_fired,
            "reason": sampler.reason,
            "cohort_rate": float(sampler.cohort_rate) if sampler.cohort_rate is not None else None,
        } if sampler else None),
        "events": [{
            "event_id": str(event.event_id),
            "ts": event.ts.isoformat() if event.ts else None,
            "event_type": event.event_type,
            "channel": event.channel,
            "payload": event.payload,
        } for event in events],
        "checks": {check.value: payload for check, payload in grouped.items()},
        "flag": ({
            "flag_id": str(flag.flag_id),
            "severity": flag.severity,
            "asi_categories": flag.asi_categories,
            "status": flag.status,
        } if flag else None),
        "incident": ({
            "incident_id": str(incident.incident_id),
            "state": incident.state,
            "severity": incident.severity,
        } if incident else None),
    }


__all__ = ["agent_router"]
