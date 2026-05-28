"""Windows involuntary backend — Sysmon subscriber + translator (PRD §9.2.2).

Implements :class:`~auditor.involuntary.base.InvoluntaryObserver` on Windows. On ``start`` it resolves
the harness process tree (the harness PID plus its descendants via ``psutil``), starts a
:class:`~involuntary.windows_sysmon.subscriber.SysmonSubscriber` scoped to those PIDs, and registers a
callback that translates each rendered Sysmon XML record into a ``Syscall*`` event (via
:func:`involuntary.windows_sysmon.translator.translate`) and pushes it onto an ``asyncio.Queue``.
``events()`` drains that queue as an async generator; ``stop`` cancels the subscription.

Because the subscriber delivers events on a pywin32 thread (not the event loop), the callback hops
back onto the loop with ``call_soon_threadsafe`` before touching the queue.

All ``win32*`` / ``psutil`` imports are kept **inside methods** so importing this module never
requires the Windows-only ``windows`` extra (``pip install -e ".[windows]"``); the translator import
is likewise lazy so a missing ``involuntary`` namespace path cannot break module import.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from uuid import UUID

from auditor.events.schemas import BaseEvent
from auditor.involuntary.base import InvoluntaryObserver
from auditor.logging import get_logger

log = get_logger("auditor.involuntary.windows")

# Sentinel pushed onto the queue by stop() to unblock a parked events() consumer.
_SENTINEL = object()


class SysmonObserver(InvoluntaryObserver):
    """Sysmon-backed involuntary observer for the harness process tree."""

    def __init__(self, *, queue_maxsize: int = 0) -> None:
        self._queue: asyncio.Queue[object] = asyncio.Queue(maxsize=queue_maxsize)
        self._subscriber: object | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._run_id: UUID | None = None
        self._tenant_id: UUID | None = None
        self._started = False

    @staticmethod
    def _process_tree(harness_pid: int) -> set[int]:
        """Harness PID plus its current descendants (best-effort via psutil)."""
        import psutil

        pids = {harness_pid}
        try:
            proc = psutil.Process(harness_pid)
            pids.update(child.pid for child in proc.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return pids

    async def start(self, harness_pid: int, run_id: UUID) -> None:
        """Begin observing the harness tree's Sysmon events for ``run_id``.

        ``tenant_id`` is not part of the ABC signature; until the observer is wired into the run
        context it defaults to ``run_id`` (the divergence detector keys on ``run_id``). This keeps
        the produced events schema-valid without inventing a second identifier here.
        """
        from involuntary.windows_sysmon.subscriber import SysmonSubscriber
        from involuntary.windows_sysmon.translator import translate

        self._loop = asyncio.get_running_loop()
        self._run_id = run_id
        self._tenant_id = run_id  # see docstring — placeholder until run-context wiring.

        process_ids = self._process_tree(harness_pid)
        subscriber = SysmonSubscriber(process_ids=process_ids)

        def _on_xml(xml_str: str) -> None:
            # Called on a pywin32 thread. Do the (pure) translation here, then hand the finished
            # event to the loop thread — asyncio.Queue is not thread-safe.
            try:
                event = translate(xml_str, run_id=run_id, tenant_id=self._tenant_id)
            except Exception as exc:  # noqa: BLE001 - a malformed record must not kill the stream
                log.warning("involuntary.windows.translate_failed", run_id=str(run_id), error=str(exc))
                return
            if event is None:
                return
            loop = self._loop
            if loop is not None:
                loop.call_soon_threadsafe(self._queue.put_nowait, event)

        subscriber.start(_on_xml)
        self._subscriber = subscriber
        self._started = True
        log.info(
            "involuntary.windows.started",
            run_id=str(run_id),
            harness_pid=harness_pid,
            tracked_pids=len(process_ids),
        )

    async def stop(self, run_id: UUID) -> None:
        """Stop the subscription and unblock any parked ``events()`` consumer."""
        subscriber = self._subscriber
        self._subscriber = None
        if subscriber is not None:
            subscriber.stop()  # type: ignore[attr-defined]
        self._started = False
        self._queue.put_nowait(_SENTINEL)
        log.info("involuntary.windows.stopped", run_id=str(run_id))

    async def events(self) -> AsyncIterator[BaseEvent]:
        """Yield normalized involuntary events until ``stop`` is called."""
        while True:
            item = await self._queue.get()
            if item is _SENTINEL:
                return
            yield item  # type: ignore[misc]


__all__ = ["SysmonObserver"]
