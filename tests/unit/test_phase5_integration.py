"""Phase 5 integration glue: HITL decision→enforcer wiring, app router wiring, replay perf bound."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import UUID, uuid4

from auditor.api.hitl_routes import _apply_enforcement
from auditor.api.replay import build_export_bundle, verify_export_bundle
from auditor.detectors.base import Trace
from auditor.events.schemas import ToolCallStart


class _RecordingEnforcer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def pause(self, run_id) -> None:
        self.calls.append(("pause", run_id))

    async def resume(self, run_id) -> None:
        self.calls.append(("resume", run_id))

    async def abort(self, run_id) -> None:
        self.calls.append(("abort", run_id))


# --------------------------------------------------------------------------- decision → enforcer


async def test_continue_decision_resumes_run(monkeypatch) -> None:
    enforcer = _RecordingEnforcer()
    monkeypatch.setattr("auditor.enforcement.get_enforcer", lambda: enforcer)
    run_id = str(uuid4())
    result = await _apply_enforcement("continue", run_id)
    assert result == {"action": "resume", "ok": True}
    assert enforcer.calls == [("resume", UUID(run_id))]


async def test_abort_and_quarantine_decisions_abort_run(monkeypatch) -> None:
    enforcer = _RecordingEnforcer()
    monkeypatch.setattr("auditor.enforcement.get_enforcer", lambda: enforcer)
    await _apply_enforcement("abort", str(uuid4()))
    await _apply_enforcement("quarantine", str(uuid4()))
    assert [c[0] for c in enforcer.calls] == ["abort", "abort"]


async def test_unknown_decision_is_noop(monkeypatch) -> None:
    enforcer = _RecordingEnforcer()
    monkeypatch.setattr("auditor.enforcement.get_enforcer", lambda: enforcer)
    assert await _apply_enforcement("comment", str(uuid4())) == {"action": "none"}
    assert enforcer.calls == []


async def test_enforcement_failure_is_reported_not_raised(monkeypatch) -> None:
    class _Boom:
        async def resume(self, run_id):
            raise RuntimeError("not registered")

    monkeypatch.setattr("auditor.enforcement.get_enforcer", lambda: _Boom())
    result = await _apply_enforcement("continue", str(uuid4()))
    assert result["action"] == "resume" and result["ok"] is False and "error" in result


# --------------------------------------------------------------------------- app router wiring


def test_app_exposes_hitl_routes() -> None:
    from auditor.main import create_app

    paths = {getattr(r, "path", "") for r in create_app().routes}
    assert "/hitl/flags" in paths
    assert "/hitl/flags/{flag_id}/decisions" in paths
    assert "/health" in paths  # existing route still present


# --------------------------------------------------------------------------- replay perf (§15: <5s/500ev)


def test_replay_bundle_of_500_events_is_fast() -> None:
    run_id, tenant_id, agent_id = uuid4(), uuid4(), uuid4()
    t0 = datetime(2026, 5, 27, tzinfo=UTC)
    events = [
        ToolCallStart(
            event_id=uuid4(), run_id=run_id, tenant_id=tenant_id, span_id=uuid4(), ts=t0,
            agent_id=agent_id, tool_name="kb_search", tool_args={"q": f"item-{i}"},
        )
        for i in range(500)
    ]
    trace = Trace(run_id=run_id, tenant_id=tenant_id, declared_goal="triage", events=events)

    start = time.perf_counter()
    bundle = build_export_bundle(trace, secret=b"demo-secret")
    elapsed = time.perf_counter() - start

    assert elapsed < 5.0  # PRD §15 Phase-5 acceptance: replay of a 500-event run < 5s
    assert len(bundle["events"]) == 500
    assert verify_export_bundle(bundle, secret=b"demo-secret")
