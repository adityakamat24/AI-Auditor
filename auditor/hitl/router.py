"""HITL router (PRD §9.10.1) — severity-tiered routing of aggregated flags.

Dispatches a :class:`~auditor.verdicts.aggregator.Flag` to the correct
review path based on its severity:

* **CRITICAL** — pause the run (via the enforcer), enqueue in Redis (4 h TTL),
  and page via Slack.  Captures a checkpoint before pausing.
* **HIGH** — enqueue in Redis (4 h TTL) + Slack notify.  No pause.
* **MEDIUM** — append to the daily per-tenant digest list.  No pause or page.
* **LOW** — log only.

All collaborators (enforcer, queue, notifier) are constructor-injectable so
they can be replaced with fakes in unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from auditor.logging import get_logger
from auditor.verdicts.schemas import Severity

if TYPE_CHECKING:
    from auditor.verdicts.aggregator import Flag

log = get_logger("auditor.hitl.router")

# TTL applied to CRITICAL and HIGH queue entries.
_HIGH_TTL_S: int = 4 * 60 * 60  # 4 hours


@dataclass
class RoutingResult:
    """Summary of what the router did for a flag."""

    tier: str
    paused: bool = False
    queued: bool = False
    notified: bool = False
    digested: bool = False
    checkpoint_uri: str | None = None
    pause_error: str | None = None


class HitlRouter:
    """Routes flags to the appropriate HITL path based on severity.

    Parameters
    ----------
    enforcer:
        Auditor enforcement backstop used to pause a run.  Defaults to the
        platform enforcer returned by :func:`~auditor.enforcement.get_enforcer`.
    queue:
        :class:`~auditor.hitl.queue.HitlQueue` instance for Redis-backed storage.
    notifier:
        :class:`~auditor.hitl.notifier.SlackNotifier` instance.
    checkpoint:
        :class:`~auditor.hitl.checkpoint.CheckpointCapture` instance.
    ui_base_url:
        Optional base URL for the HITL review UI (passed to the notifier for
        the "View flag" link).
    """

    def __init__(
        self,
        enforcer: object | None = None,
        queue: object | None = None,
        notifier: object | None = None,
        checkpoint: object | None = None,
        ui_base_url: str | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._queue = queue
        self._notifier = notifier
        self._checkpoint = checkpoint
        self._ui_base_url = ui_base_url

    def _get_enforcer(self) -> object:
        if self._enforcer is None:
            from auditor.enforcement import get_enforcer

            self._enforcer = get_enforcer()
        return self._enforcer

    def _get_queue(self) -> object:
        if self._queue is None:
            from auditor.hitl.queue import HitlQueue

            self._queue = HitlQueue()
        return self._queue

    def _get_notifier(self) -> object:
        if self._notifier is None:
            from auditor.hitl.notifier import SlackNotifier

            self._notifier = SlackNotifier()
        return self._notifier

    def _get_checkpoint(self) -> object:
        if self._checkpoint is None:
            from auditor.hitl.checkpoint import CheckpointCapture

            self._checkpoint = CheckpointCapture(enforcer=self._enforcer)
        return self._checkpoint

    def _ui_url(self, flag: Flag) -> str | None:
        if self._ui_base_url:
            return f"{self._ui_base_url.rstrip('/')}/flags/{flag.flag_id}"
        return None

    async def route(self, flag: Flag) -> RoutingResult:
        """Route *flag* to the appropriate HITL tier.

        Parameters
        ----------
        flag:
            An aggregated :class:`~auditor.verdicts.aggregator.Flag`.

        Returns
        -------
        RoutingResult
            A summary of the actions taken.
        """
        severity = str(flag.severity).lower()

        if severity == Severity.CRITICAL:
            return await self._route_critical(flag)
        if severity == Severity.HIGH:
            return await self._route_high(flag)
        if severity == Severity.MEDIUM:
            return await self._route_medium(flag)
        # LOW (and anything unexpected) — log only.
        return await self._route_low(flag)

    # ------------------------------------------------------------------
    # Severity handlers
    # ------------------------------------------------------------------

    async def _route_critical(self, flag: Flag) -> RoutingResult:
        result = RoutingResult(tier="critical")

        # 1. Capture checkpoint (best-effort before pausing).
        try:
            checkpoint = self._get_checkpoint()
            uri = await checkpoint.capture(flag.run_id, flag.tenant_id)  # type: ignore[union-attr]
            result.checkpoint_uri = uri
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.checkpoint_failed", flag_id=str(flag.flag_id), error=str(exc))

        # 2. Pause the run — tolerate missing PID gracefully.
        try:
            enforcer = self._get_enforcer()
            await enforcer.pause(flag.run_id)  # type: ignore[union-attr]
            result.paused = True
            log.info("hitl.router.paused", run_id=str(flag.run_id), flag_id=str(flag.flag_id))
        except Exception as exc:  # noqa: BLE001
            result.pause_error = str(exc)
            log.warning(
                "hitl.router.pause_failed",
                run_id=str(flag.run_id),
                flag_id=str(flag.flag_id),
                error=str(exc),
            )

        # 3. Enqueue.
        try:
            queue = self._get_queue()
            await queue.enqueue(flag, ttl_s=_HIGH_TTL_S)  # type: ignore[union-attr]
            result.queued = True
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.enqueue_failed", flag_id=str(flag.flag_id), error=str(exc))

        # 4. Notify.
        try:
            notifier = self._get_notifier()
            result.notified = await notifier.notify(flag, ui_url=self._ui_url(flag))  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.notify_failed", flag_id=str(flag.flag_id), error=str(exc))

        log.warning(
            "hitl.router.critical",
            flag_id=str(flag.flag_id),
            run_id=str(flag.run_id),
            paused=result.paused,
            queued=result.queued,
            notified=result.notified,
        )
        return result

    async def _route_high(self, flag: Flag) -> RoutingResult:
        result = RoutingResult(tier="high")

        # Enqueue with 4 h TTL.
        try:
            queue = self._get_queue()
            await queue.enqueue(flag, ttl_s=_HIGH_TTL_S)  # type: ignore[union-attr]
            result.queued = True
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.enqueue_failed", flag_id=str(flag.flag_id), error=str(exc))

        # Notify.
        try:
            notifier = self._get_notifier()
            result.notified = await notifier.notify(flag, ui_url=self._ui_url(flag))  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.notify_failed", flag_id=str(flag.flag_id), error=str(exc))

        log.info(
            "hitl.router.high",
            flag_id=str(flag.flag_id),
            run_id=str(flag.run_id),
            queued=result.queued,
            notified=result.notified,
        )
        return result

    async def _route_medium(self, flag: Flag) -> RoutingResult:
        result = RoutingResult(tier="medium")

        try:
            queue = self._get_queue()
            await queue.append_digest(flag)  # type: ignore[union-attr]
            result.digested = True
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.router.digest_failed", flag_id=str(flag.flag_id), error=str(exc))

        log.info(
            "hitl.router.medium",
            flag_id=str(flag.flag_id),
            run_id=str(flag.run_id),
            digested=result.digested,
        )
        return result

    async def _route_low(self, flag: Flag) -> RoutingResult:
        log.info(
            "hitl.router.low",
            flag_id=str(flag.flag_id),
            run_id=str(flag.run_id),
            severity=str(flag.severity),
        )
        return RoutingResult(tier="low")


__all__ = ["HitlRouter", "RoutingResult"]
