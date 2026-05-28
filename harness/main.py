"""Harness entrypoint (Phase 2).

Connects to the auditor over IPC (mTLS when certs are provided) and runs a mode:
- ``scripted`` (default): declares intent and drives a few GATED tool calls - a benign ALLOW and an
  ``exec_shell`` DENY - demonstrating the inline gate end-to-end. Key-free.
- ``groupchat``: runs the AG2 ITSM two-agent group chat (requires an Anthropic key via LiteLLM).

Fail-closed: if the auditor is unreachable the harness refuses to run (non-zero exit).
"""

from __future__ import annotations

import asyncio
import os
import ssl
from uuid import UUID

from auditor.config import Settings
from auditor.ids import uuid7
from auditor.logging import configure_logging, get_logger

from harness.config import harness_settings, run_id_from_env, tenant_id_from_env
from harness.telemetry import Telemetry
from harness.telemetry.sdk import GateDeniedError

log = get_logger("harness.main")


def _client_ssl_context(settings: Settings) -> ssl.SSLContext | None:
    cert, key, ca = (os.environ.get(k) for k in ("HARNESS_CERT", "HARNESS_KEY", "HARNESS_CA"))
    if settings.ipc_mtls_enabled and cert and key and ca:
        from auditor.ipc.auth import build_client_context

        return build_client_context(cert, key, ca)
    return None


async def _run_scripted(telemetry: Telemetry, agent_id: UUID) -> None:
    await telemetry.declare_intent(agent_id, "demo: triage a VPN ticket", ["search KB", "create ticket"])

    async with telemetry.tool_call(agent_id, "kb_search", {"query": "vpn setup"}) as decision:
        log.info("harness.tool_allowed", tool="kb_search", decision=decision)

    async with telemetry.tool_call(
        agent_id, "create_ticket", {"subject": "VPN access issue"}, declared_purpose="create an IT ticket"
    ) as decision:
        log.info("harness.tool_allowed", tool="create_ticket", decision=decision)

    try:
        async with telemetry.tool_call(agent_id, "exec_shell", {"cmd": "id"}):
            log.warning("harness.exec_unexpectedly_allowed")
    except GateDeniedError as exc:
        log.info("harness.tool_denied", tool="exec_shell", reasons=exc.reasons)


async def _run_groupchat(settings: Settings, telemetry: Telemetry) -> bool:
    if not settings.judge_live:
        log.warning("harness.groupchat_skipped", reason="no ANTHROPIC_API_KEY; using scripted mode")
        return False
    from harness.agents.base import run_itsm_groupchat

    result = await run_itsm_groupchat(
        settings, telemetry, "A user cannot connect to the VPN. Triage and resolve."
    )
    log.info("harness.groupchat_done", result=str(result)[:200])
    return True


async def _run_agent(settings: Settings, telemetry: Telemetry, agent_id: UUID) -> bool:
    """Run a real general-purpose agent live on an arbitrary task (HARNESS_TASK). Needs a key."""
    if not settings.judge_live:
        log.warning("harness.agent_skipped", reason="no ANTHROPIC_API_KEY; using scripted mode")
        return False
    from harness.agents.base import run_agent_task

    task = os.environ.get("HARNESS_TASK") or "Summarize the file work/notes.txt into work/summary.txt."
    log.info("harness.agent_task", task=task[:200])
    # Record the task as the run's declared instruction so the auditor's judge can grade adherence.
    await telemetry.declare_intent(agent_id, task, [task])
    result = await run_agent_task(settings, telemetry, task, agent_id=agent_id)
    # Echo the agent's final response back as an intent.declare with a [response] prefix so the chat UI
    # can render it. (Repurposes the existing event type to avoid a proto change for the demo.)
    response_text = str(result or "").strip()
    if response_text:
        await telemetry.declare_intent(agent_id, f"[response] {response_text[:3500]}", [])
    log.info("harness.agent_done", result=response_text[:200])
    return True


async def amain() -> int:
    settings = harness_settings()
    configure_logging(settings)
    run_id = run_id_from_env()
    tenant_id = tenant_id_from_env()
    agent_id = uuid7()
    mode = os.environ.get("HARNESS_MODE", "scripted")
    ssl_context = _client_ssl_context(settings)

    try:
        telemetry = await Telemetry.connect(
            run_id, tenant_id, settings,
            ssl_context=ssl_context,
            server_hostname="auditor.local" if ssl_context else None,
        )
    except (ConnectionError, OSError, ssl.SSLError) as exc:
        log.error("harness.connect_failed", error=str(exc), note="fail-closed: auditor unreachable")
        return 1

    try:
        if mode == "agent":
            ran = await _run_agent(settings, telemetry, agent_id)
        elif mode == "groupchat":
            ran = await _run_groupchat(settings, telemetry)
        else:
            ran = False
        if not ran:
            await _run_scripted(telemetry, agent_id)
    finally:
        await telemetry.close()

    log.info("harness.exit_clean", run_id=str(run_id), mode=mode)
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
