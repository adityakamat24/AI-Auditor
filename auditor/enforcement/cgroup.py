"""Linux cgroup-v2 freeze enforcer (PRD §9.5.3) — Linux only; verified on a Linux box / CI.

Pauses a run by writing ``1`` to its cgroup's ``cgroup.freeze`` (freezing the whole subtree), resumes
with ``0``, and aborts via ``cgroup.kill`` (or SIGKILL fallback). Filesystem writes are confined to
methods so this module imports on any platform.
"""

from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path
from uuid import UUID

from auditor.enforcement.base import Enforcer
from auditor.logging import get_logger

log = get_logger("auditor.enforcement.cgroup")


class CgroupEnforcer(Enforcer):
    def __init__(self, cgroup_root: str = "/sys/fs/cgroup/auditor") -> None:
        self._root = Path(cgroup_root)
        self._pids: dict[str, int] = {}

    def register(self, run_id: UUID | str, pid: int) -> None:
        self._pids[str(run_id)] = pid

    def _cgroup_dir(self, run_id: UUID) -> Path:
        return self._root / f"run_{run_id}"

    async def _write(self, run_id: UUID, filename: str, value: str) -> None:
        path = self._cgroup_dir(run_id) / filename
        await asyncio.to_thread(path.write_text, value)

    async def pause(self, run_id: UUID) -> None:
        await self._write(run_id, "cgroup.freeze", "1\n")
        log.info("enforcement.frozen", run_id=str(run_id))

    async def resume(self, run_id: UUID) -> None:
        await self._write(run_id, "cgroup.freeze", "0\n")
        log.info("enforcement.thawed", run_id=str(run_id))

    async def abort(self, run_id: UUID) -> None:
        kill_file = self._cgroup_dir(run_id) / "cgroup.kill"
        try:
            await asyncio.to_thread(kill_file.write_text, "1\n")
        except OSError:
            pid = self._pids.get(str(run_id))
            if pid is not None:
                with __import__("contextlib").suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        log.info("enforcement.aborted", run_id=str(run_id))


__all__ = ["CgroupEnforcer"]
