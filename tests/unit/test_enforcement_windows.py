"""Windows enforcement backstop: pause/resume/abort a real child process via psutil."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows enforcement backstop")


async def test_pause_resume_abort() -> None:
    import psutil
    from auditor.enforcement.windows_jobobject import WindowsJobObjectEnforcer

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])  # noqa: ASYNC220
    run_id = uuid4()
    enforcer = WindowsJobObjectEnforcer()
    enforcer.register(run_id, proc.pid)
    try:
        await enforcer.pause(run_id)
        assert psutil.Process(proc.pid).status() == psutil.STATUS_STOPPED

        await enforcer.resume(run_id)
        assert psutil.Process(proc.pid).status() != psutil.STATUS_STOPPED

        await enforcer.abort(run_id)
        terminated = False
        for _ in range(60):
            if proc.poll() is not None:
                terminated = True
                break
            await asyncio.sleep(0.05)
        assert terminated, "process was not terminated by abort()"
    finally:
        if proc.poll() is None:
            proc.kill()
