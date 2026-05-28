"""Windows enforcement backstop (PRD §9.5.3).

Suspends / resumes / terminates a run's harness **process tree** via psutil (which wraps
``NtSuspendProcess``/``NtResumeProcess``). When a Job Object handle is registered for a run, ``abort``
terminates it atomically (``TerminateJobObject`` - no orphans); otherwise it kills the psutil tree.
``quarantine`` leaves the tree suspended and captures a memory dump for forensics.

psutil/pywin32 are imported lazily so importing this module never requires the Windows extra.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

from auditor.enforcement.base import Enforcer
from auditor.logging import get_logger

log = get_logger("auditor.enforcement.windows")


class WindowsJobObjectEnforcer(Enforcer):
    def __init__(self) -> None:
        self._pids: dict[str, int] = {}
        self._jobs: dict[str, object] = {}  # run_id -> win32 job handle (optional)

    def register(self, run_id: UUID | str, pid: int, job_handle: object | None = None) -> None:
        key = str(run_id)
        self._pids[key] = pid
        if job_handle is not None:
            self._jobs[key] = job_handle

    def unregister(self, run_id: UUID | str) -> None:
        key = str(run_id)
        self._pids.pop(key, None)
        self._jobs.pop(key, None)

    def _pid(self, run_id: UUID | str) -> int | None:
        return self._pids.get(str(run_id))

    def _tree(self, pid: int):
        import psutil

        proc = psutil.Process(pid)
        return [proc, *proc.children(recursive=True)]

    async def pause(self, run_id: UUID) -> None:
        pid = self._pid(run_id)
        if pid is None:
            return

        def _do() -> None:
            import psutil

            for p in self._tree(pid):
                try:
                    p.suspend()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        await asyncio.to_thread(_do)
        log.info("enforcement.paused", run_id=str(run_id), pid=pid)

    async def resume(self, run_id: UUID) -> None:
        pid = self._pid(run_id)
        if pid is None:
            return

        def _do() -> None:
            import psutil

            for p in self._tree(pid):
                try:
                    p.resume()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        await asyncio.to_thread(_do)
        log.info("enforcement.resumed", run_id=str(run_id), pid=pid)

    async def abort(self, run_id: UUID) -> None:
        key = str(run_id)
        job = self._jobs.get(key)
        pid = self._pid(run_id)

        def _do() -> None:
            if job is not None:  # atomic kill of the whole job, no orphans
                import win32job

                win32job.TerminateJobObject(job, 1)
                return
            if pid is None:
                return
            import psutil

            for p in self._tree(pid):
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        await asyncio.to_thread(_do)
        self.unregister(run_id)
        log.info("enforcement.aborted", run_id=str(run_id), pid=pid)

    async def quarantine(self, run_id: UUID, out_dir: str) -> str | None:
        """Suspend the tree and write a memory dump (best-effort). Returns the dump path or None."""
        await self.pause(run_id)
        pid = self._pid(run_id)
        if pid is None:
            return None
        dump_path = str(Path(out_dir) / f"{run_id}.dmp")

        def _dump() -> str | None:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            import ctypes

            kernel32 = ctypes.windll.kernel32
            dbghelp = ctypes.windll.dbghelp
            h_proc = kernel32.OpenProcess(0x1F0FFF, False, pid)  # PROCESS_ALL_ACCESS
            if not h_proc:
                return None
            h_file = kernel32.CreateFileW(dump_path, 0x40000000, 0, None, 2, 0x80, None)
            if h_file == -1:
                kernel32.CloseHandle(h_proc)
                return None
            ok = dbghelp.MiniDumpWriteDump(h_proc, pid, h_file, 0x00000002, None, None, None)
            kernel32.CloseHandle(h_file)
            kernel32.CloseHandle(h_proc)
            return dump_path if ok else None

        try:
            result = await asyncio.to_thread(_dump)
        except OSError as exc:  # noqa: BLE001
            log.warning("enforcement.quarantine_dump_failed", run_id=str(run_id), error=str(exc))
            result = None
        log.info("enforcement.quarantined", run_id=str(run_id), dump=result)
        return result


__all__ = ["WindowsJobObjectEnforcer"]
