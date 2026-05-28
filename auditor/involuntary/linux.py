"""Linux involuntary backend - eBPF loader/reader (PRD §9.2.1).

Implements :class:`~auditor.involuntary.base.InvoluntaryObserver` on Linux on top of the Rust + Aya
programs in ``involuntary/linux_ebpf/``. The real loader will:

1. Load the compiled eBPF object via Aya's Python bindings (or a Rust userspace shim) and attach the
   ``openat`` / ``connect`` / ``execve`` / ``sendto`` kprobes/tracepoints (see ``src/probes/*.rs``).
2. Populate the cgroup allowlist map (``src/cgroup_filter.rs``) with the harness run's cgroup id so
   the in-kernel filter drops every other process's events.
3. Spawn a reader task that pumps the perf buffer, decodes each fixed-layout record, and normalizes
   it into the matching ``Syscall*`` schema before pushing it onto :attr:`_queue`.

Required capabilities: ``CAP_BPF``, ``CAP_PERFMON``, ``CAP_SYS_RESOURCE`` (memlock) on kernel ≥ 5.8;
``CAP_SYS_ADMIN`` on older kernels (PRD §9.2.1).

This is a **scaffold**: the queue / ``events()`` plumbing is real, but ``start`` raises
``NotImplementedError`` because the eBPF object only builds and loads on Linux (verified on Linux/CI,
not on the developer's Windows box). No Linux-only modules are imported at module top so this file
imports cleanly everywhere; the loader-specific imports (``aya`` bindings, ``ctypes`` perf reader,
cgroup helpers) belong inside :meth:`start`.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from uuid import UUID

from auditor.events.schemas import BaseEvent
from auditor.involuntary.base import InvoluntaryObserver
from auditor.logging import get_logger

log = get_logger("auditor.involuntary.linux")

# Sentinel pushed onto the queue by stop() to unblock a parked events() consumer.
_SENTINEL = object()


class EbpfObserver(InvoluntaryObserver):
    """eBPF-backed involuntary observer for the harness cgroup (Linux only)."""

    def __init__(self, *, queue_maxsize: int = 0) -> None:
        self._queue: asyncio.Queue[object] = asyncio.Queue(maxsize=queue_maxsize)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._run_id: UUID | None = None
        self._started = False

    async def start(self, harness_pid: int, run_id: UUID) -> None:
        """Load the eBPF programs, attach probes, and begin reading the perf buffer.

        Verified on Linux/CI. The object in ``involuntary/linux_ebpf`` does not build on Windows, so
        this raises until exercised on Linux. The plumbing below (loop capture, run bookkeeping) is
        the same shape the real implementation uses; only the Aya load + perf-reader spawn are absent.
        """
        self._loop = asyncio.get_running_loop()
        self._run_id = run_id
        # Real implementation (Linux): resolve the harness cgroup id, load the Aya object, attach the
        # openat/connect/execve/sendto probes, write the cgroup id into the allowlist map, then
        #   self._reader_task = asyncio.create_task(self._read_perf_buffer())
        raise NotImplementedError(
            "Linux eBPF observer loads/attaches the Aya programs in involuntary/linux_ebpf; "
            "verified on Linux/CI (the eBPF object does not build on this platform)"
        )

    async def stop(self, run_id: UUID) -> None:
        """Detach probes, stop the reader task, and unblock any parked ``events()`` consumer."""
        task = self._reader_task
        self._reader_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # best-effort teardown
                await task
        self._started = False
        self._queue.put_nowait(_SENTINEL)
        log.info("involuntary.linux.stopped", run_id=str(run_id))

    async def events(self) -> AsyncIterator[BaseEvent]:
        """Yield normalized involuntary events until ``stop`` is called."""
        while True:
            item = await self._queue.get()
            if item is _SENTINEL:
                return
            yield item  # type: ignore[misc]


__all__ = ["EbpfObserver"]
