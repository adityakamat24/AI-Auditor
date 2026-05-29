"""Lifecycle tests for :class:`auditor.harness_runner.HarnessRun`.

Covers the four reviewer findings end-to-end:

  1. **Status transitions** - ``pending → running → completed`` via the reaper thread (no
     dependency on ``proc.poll()`` from the API side).
  2. **FD + registry cleanup** - the log handle closes after the child exits; ``_LIVE_RUNS``
     drains via the TTL sweep.
  3. **Termination escalation** - ``terminate(timeout)`` escalates to kill if the child won't
     exit on SIGTERM.
  4. **Signal isolation** - the child gets its own session / process group (POSIX) or process
     group + breakaway (Windows) so SIGINT to the test doesn't cascade.

The tests spawn a real ``python -c`` subprocess via ``command=``, which lets us exercise the
class without going through ``harness/main.py``. ``data_dir=tmp_path`` makes cert minting
deterministic and self-contained.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from uuid import UUID

import pytest

from auditor.harness_runner import (
    _LIVE_RUNS,
    HarnessRun,
    _sweep_expired_runs,
    get_run,
)

DEMO_TENANT = UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture(autouse=True)
def _isolate_live_runs() -> None:
    """Stop tests from leaking registry entries into each other."""
    _LIVE_RUNS.clear()
    yield
    # Best-effort cleanup: terminate anything we left running.
    for run in list(_LIVE_RUNS.values()):
        try:
            run.terminate(timeout=1.0)
        except Exception:  # noqa: BLE001,S110 - cleanup, never fail tests on teardown
            pass
    _LIVE_RUNS.clear()


def _make_run(tmp_path: Path) -> HarnessRun:
    return HarnessRun.from_request(
        task="lifecycle test",
        max_turns=1,
        tenant_id=DEMO_TENANT,
        data_dir=str(tmp_path),
        log_dir=tmp_path / "logs",
    )


def _short_sleep_command(seconds: float) -> list[str]:
    """Command that exits cleanly after ``seconds`` seconds without printing anything."""
    return [sys.executable, "-c", f"import time; time.sleep({seconds})"]


def _ignore_sigterm_command(seconds: float) -> list[str]:
    """Command that ignores SIGTERM and only dies on SIGKILL. POSIX-only - on Windows there's
    no SIGTERM-vs-SIGKILL distinction, ``terminate()`` is already the hard kill."""
    return [
        sys.executable,
        "-c",
        (
            "import signal, time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            f"time.sleep({seconds})"
        ),
    ]


def _wait_for_status(run: HarnessRun, target: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if run.status == target:
            return
        if run.status.startswith("exited"):
            return  # close enough for assertions to inspect
        time.sleep(0.02)
    raise AssertionError(
        f"run {run.run_id} did not reach status {target!r} within {timeout}s "
        f"(last status: {run.status!r})"
    )


@pytest.mark.timeout(15)
class TestLifecycle:
    """Spawn a short-lived subprocess and watch the lifecycle methods drive it to terminal state."""

    def test_pending_to_running_to_completed(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        assert run.status == "pending"
        run.start(command=_short_sleep_command(0.2))
        assert run.status == "running"
        assert run.pid is not None
        assert run.started_at is not None
        _wait_for_status(run, "completed", timeout=3.0)
        assert run.exit_code == 0
        assert run.ended_at is not None

    def test_log_handle_closes_after_child_exits(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        run.start(command=_short_sleep_command(0.1))
        _wait_for_status(run, "completed", timeout=3.0)
        # The reaper closes _log_handle as part of finalization.
        assert run._log_handle is not None
        assert run._log_handle.closed, "log file FD should be closed after the child exits"

    def test_registered_in_live_runs(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        run.start(command=_short_sleep_command(0.1))
        assert get_run(run.run_id) is run
        _wait_for_status(run, "completed", timeout=3.0)
        # Still registered (TTL grace period); the sweep is what drops it eventually.
        assert get_run(run.run_id) is run

    def test_log_file_was_written(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        run.start(command=[sys.executable, "-c", "print('hello from child')"])
        _wait_for_status(run, "completed", timeout=3.0)
        assert run.log_path is not None
        assert run.log_path.exists()
        assert "hello from child" in run.log_path.read_text()


@pytest.mark.timeout(15)
class TestTermination:
    """terminate() should escalate to kill if the child refuses to die on SIGTERM."""

    def test_terminate_kills_polite_child(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        run.start(command=_short_sleep_command(60))  # would run for a minute
        time.sleep(0.1)
        assert run.status == "running"
        run.terminate(timeout=3.0)
        _wait_for_status(run, "exited", timeout=3.0)
        assert run.exit_code != 0  # signaled, not clean exit

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="No SIGTERM/SIGKILL distinction on Windows - terminate() is already hard kill",
    )
    def test_terminate_escalates_to_kill_when_sigterm_ignored(self, tmp_path: Path) -> None:
        run = _make_run(tmp_path)
        run.start(command=_ignore_sigterm_command(60))
        time.sleep(0.1)
        assert run.status == "running"
        # terminate() sends SIGTERM, waits, escalates to SIGKILL. Whole thing must finish quickly.
        t0 = time.monotonic()
        run.terminate(timeout=1.0)
        elapsed = time.monotonic() - t0
        _wait_for_status(run, "exited", timeout=3.0)
        assert elapsed < 2.5, f"terminate took too long: {elapsed:.2f}s"


@pytest.mark.timeout(15)
class TestSignalIsolation:
    """The child should be in its own session/process group so signals to us don't cascade.
    We assert at the OS level - getpgid on POSIX, no good cross-platform check on Windows."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX session/group test")
    def test_child_is_in_its_own_session(self, tmp_path: Path) -> None:
        # Have the child print its own session id (sid). If start_new_session=True worked,
        # the child's sid equals its pid (it's the session leader) and differs from ours.
        run = _make_run(tmp_path)
        run.start(command=[sys.executable, "-c", "import os; print(os.getsid(0))"])
        _wait_for_status(run, "completed", timeout=3.0)
        assert run.log_path is not None
        child_sid = int(run.log_path.read_text().strip())
        # The child is the session leader: its sid equals its pid.
        assert child_sid == run.pid, (
            f"child sid {child_sid} != child pid {run.pid} - start_new_session didn't take"
        )
        # And it's NOT in our session.
        assert child_sid != os.getsid(0)


@pytest.mark.timeout(15)
class TestSweepExpiredRuns:
    """Bounded growth: completed runs eventually leave the registry."""

    def test_completed_runs_kept_until_ttl(self, tmp_path: Path, monkeypatch) -> None:
        run = _make_run(tmp_path)
        run.start(command=_short_sleep_command(0.05))
        _wait_for_status(run, "completed", timeout=3.0)
        # With the real TTL, the run stays registered.
        _sweep_expired_runs()
        assert get_run(run.run_id) is run

    def test_completed_runs_dropped_past_ttl(self, tmp_path: Path, monkeypatch) -> None:
        run = _make_run(tmp_path)
        run.start(command=_short_sleep_command(0.05))
        _wait_for_status(run, "completed", timeout=3.0)
        # Shrink TTL to 0 - any completed run is immediately stale.
        monkeypatch.setattr("auditor.harness_runner._REGISTRY_TTL_SECONDS", 0)
        _sweep_expired_runs()
        assert get_run(run.run_id) is None
