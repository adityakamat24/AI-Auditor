"""Owned lifecycle for the harness subprocess (PRD §9.1 control plane).

The auditor monitors a low-trust agent harness. Spawning that harness from a FastAPI route
naively (``subprocess.Popen`` + a module-global dict + a thread that walks away) creates four
coupled hazards:

1. **Env-secret leak.** ``env = dict(os.environ)`` hands the child the auditor's JWT signing key,
   DB credentials, OIDC secrets, etc. - the monitor handing its keys to the thing it's monitoring.
   A prompt-injected agent with any outbound tool can exfiltrate them and mint admin tokens.
2. **Zombie + FD leak.** Nothing reaps the child or closes the log handle if the UI stops polling.
3. **Watcher fragility.** ``proc.poll()`` is only correct under specific asyncio child-watcher
   choices; mixing raw Popen with ``asyncio.create_subprocess_*`` is a known footgun.
4. **No signal isolation.** Without ``start_new_session`` / ``CREATE_NEW_PROCESS_GROUP`` /
   ``KILL_ON_JOB_CLOSE``, SIGINT cascades and an auditor SIGKILL orphans every in-flight harness.

The cure for all four is the same: give the subprocess **one owner** that knows about it from
spawn to reap. That owner is :class:`HarnessRun`. Each instance owns the cert files, the
allowlisted env, the subprocess, the log FD, the reaper thread, and the platform-specific
isolation mechanism (PR_SET_PDEATHSIG on Linux; Job Object kill-on-handle-close on Windows via
the existing :class:`auditor.enforcement.windows_jobobject.WindowsJobObjectEnforcer`).

The route handler in :mod:`auditor.api.agent_routes` is reduced to: build the request, call
``HarnessRun.from_request(...).start()``, return the ``run_id``.
"""

from __future__ import annotations

import atexit
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import IO
from uuid import UUID

from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.ids import uuid7
from auditor.logging import get_logger

log = get_logger("auditor.harness_runner")

# ─── Env allowlist ─────────────────────────────────────────────────────────


# Exact env vars the child legitimately needs. ALLOW only what the harness's own code reads
# (HARNESS_*, IPC_MTLS_ENABLED, LITELLM_BASE_URL, ANTHROPIC_API_KEY) plus the OS-required vars
# (PATH, locale, Windows process-creation vars).
_ENV_ALLOWLIST_EXACT: frozenset[str] = frozenset(
    {
        # Process basics
        "PATH",
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
        "HOME",
        "USER",
        "TZ",
        "LANG",
        # Windows-specific - Python's import machinery breaks without these
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "TEMP",
        "TMP",
        "TMPDIR",
        # The harness's actual job
        "ANTHROPIC_API_KEY",
        "LITELLM_BASE_URL",
        "LITELLM_API_KEY",
        "AGENT_MODEL",
        "JUDGE_MODEL",
    }
)

# Prefix allowlist - locale vars and OTel public config can be safely forwarded.
_ENV_ALLOWLIST_PREFIXES: tuple[str, ...] = ("LC_",)

# Denylist by prefix - belt-and-braces on top of the explicit allowlist. Anything that smells
# like a secret is dropped even if we accidentally allowlist it. Order matters: deny wins.
_ENV_DENYLIST_PREFIXES: tuple[str, ...] = (
    "JWT_",
    "SECRET_",
    "POSTGRES_",
    "DATABASE_",
    "DB_",
    "OIDC_",
    "OAUTH_",
    "OPA_",
    "REDIS_",
    "MINIO_",
    "S3_",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_APPLICATION_",
    "FLY_API_",
    "SLACK_",
)


def build_child_env(
    parent_env: Mapping[str, str], overrides: Mapping[str, str]
) -> dict[str, str]:
    """Return a child-process environment filtered to what the harness actually needs.

    Defense in depth: deny-by-prefix first (drops ``JWT_SECRET`` / ``POSTGRES_DSN`` / OIDC
    secrets even if the allowlist accidentally lets them through), then keep only allowlisted
    vars, then apply caller-supplied ``overrides`` last and unfiltered (those are the per-run
    ``HARNESS_*`` and ``IPC_*`` vars that callers intentionally inject).

    A test asserts that representative secrets are stripped; see
    :mod:`tests.unit.test_harness_runner_env`.
    """
    out: dict[str, str] = {}
    for key, value in parent_env.items():
        if any(key.startswith(p) for p in _ENV_DENYLIST_PREFIXES):
            continue
        if key in _ENV_ALLOWLIST_EXACT or any(
            key.startswith(p) for p in _ENV_ALLOWLIST_PREFIXES
        ):
            out[key] = value
    out.update(overrides)
    return out


# ─── PR_SET_PDEATHSIG (Linux kill-on-parent-death) ─────────────────────────


def _set_pdeathsig() -> None:  # pragma: no cover - exercised end-to-end in spawn tests
    """preexec_fn: ask the kernel to send SIGTERM if our parent dies.

    Defined at module level so it's safe to use as ``preexec_fn`` (no closure state). Silent
    no-op on macOS / BSD where prctl isn't available - those platforms aren't a production
    target but we shouldn't crash on developer laptops.
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes

        PR_SET_PDEATHSIG = 1
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    except Exception:  # noqa: BLE001 - never block spawn over prctl failure
        pass


# ─── HarnessRun class ──────────────────────────────────────────────────────


# Process-wide registry. Reaper threads write to entries here; the API route reads from them.
# The atexit handler walks values to terminate stragglers on clean shutdown.
_LIVE_RUNS: dict[str, HarnessRun] = {}
_LIVE_RUNS_LOCK = threading.Lock()

# Drop registry entries whose run completed more than this many seconds ago. The UI polls
# /agent/runs/{id} for the final state; once it sees ``audited=true`` it stops, and the DB
# row is the source of truth from then on. A 30 min grace is plenty for slow pollers.
_REGISTRY_TTL_SECONDS = 30 * 60


class HarnessRun:
    """One subprocess, one owner. Tracks status, owns the log handle, runs its own reaper.

    The class is constructed in two steps so the route handler can return the ``run_id`` to
    the UI promptly:

      1. ``HarnessRun.from_request(...)`` allocates a ``run_id``, captures inputs, returns the
         object. Fast - no I/O.
      2. ``start()`` mints the cert, builds the allowlisted env, opens the log file, spawns
         the subprocess with platform-appropriate isolation, starts the reaper thread, and
         registers in :data:`_LIVE_RUNS`. Blocking - call from a worker thread via
         ``asyncio.to_thread`` if you're in async code.

    After ``start()``, the object's mutable fields (``status``, ``exit_code``, ``ended_at``)
    are written by the reaper thread under no lock - they're single-writer single-reader,
    written before ``status`` flips to terminal, read after. Python's GIL gives us that.
    """

    def __init__(
        self,
        *,
        run_id: str,
        tenant_id: UUID,
        task: str,
        max_turns: int,
        data_dir: str,
        log_dir: Path,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self.task = task
        self.max_turns = max_turns
        self._data_dir = data_dir
        self._log_dir = log_dir
        # Lifecycle fields. ``status`` is the source-of-truth field for ``_harness_status``.
        self.status: str = "pending"
        self.exit_code: int | None = None
        self.started_at: datetime | None = None
        self.ended_at: datetime | None = None
        self.log_path: Path | None = None
        self.pid: int | None = None
        # Internals.
        self._proc: subprocess.Popen[bytes] | None = None
        self._log_handle: IO | None = None
        self._reaper: threading.Thread | None = None

    @classmethod
    def from_request(
        cls,
        *,
        task: str,
        max_turns: int,
        tenant_id: UUID,
        data_dir: str,
        log_dir: Path | None = None,
    ) -> HarnessRun:
        """Allocate run_id and return a pending HarnessRun. Does not spawn - call ``start()``."""
        if log_dir is None:
            log_dir = Path(".run/agent_runs")
        return cls(
            run_id=str(uuid7()),
            tenant_id=tenant_id,
            task=task,
            max_turns=max_turns,
            data_dir=data_dir,
            log_dir=log_dir,
        )

    # ----- spawn -----

    def start(self, *, command: list[str] | None = None) -> HarnessRun:
        """Mint cert, build env, spawn the harness subprocess, register, kick off the reaper.

        ``command`` defaults to ``[sys.executable, "-m", "harness.main"]``; tests pass a
        short-lived process (e.g. ``python -c "import time; time.sleep(0.2)"``) to exercise
        the lifecycle deterministically without touching the harness package.
        """
        if self._proc is not None:
            raise RuntimeError(f"HarnessRun {self.run_id} already started")

        # Sweep stale registry entries before adding a new one (bounded growth).
        _sweep_expired_runs()

        # Cert - mint here so it's atomic with the spawn (no orphan cert files on failure).
        init_ca(self._data_dir)
        cert_path, key_path, ca_path = mint_leaf_to_files(
            self._data_dir,
            role="harness",
            run_id=self.run_id,
            tenant_id=str(self.tenant_id),
            hostname="harness.local",
        )

        # Env - allowlist + per-run overrides. The overrides are NOT filtered (they're the
        # HARNESS_* vars we intentionally inject).
        overrides = {
            "HARNESS_MODE": "agent",
            "HARNESS_TASK": self.task,
            "HARNESS_MAX_TURNS": str(self.max_turns),
            "HARNESS_CERT": str(cert_path),
            "HARNESS_KEY": str(key_path),
            "HARNESS_CA": str(ca_path),
            "HARNESS_RUN_ID": self.run_id,
            "HARNESS_TENANT_ID": str(self.tenant_id),
            "GATE_TIMEOUT_MS": os.environ.get("GATE_TIMEOUT_MS", "500"),
            # Inherit the parent's IPC_MTLS_ENABLED. Local-dev sets it true (TLS-wrapped TCP);
            # cloud single-container leaves it false (plain Unix socket). Forcing one or the
            # other breaks the other path (see git log a06a446 for the cloud-side incident).
            "IPC_MTLS_ENABLED": os.environ.get("IPC_MTLS_ENABLED", "false"),
        }
        env = build_child_env(os.environ, overrides)

        # Log file - opened here so the FD is owned by THIS object; the reaper closes it.
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self._log_dir / f"{self.run_id}.log"
        self._log_handle = self.log_path.open(  # noqa: SIM115 - lifecycle owned by reaper
            "w", encoding="utf-8", errors="replace"
        )

        # Platform-specific isolation kwargs. start_new_session on POSIX gives the child its
        # own session, isolating signal cascades. On Windows, CREATE_NEW_PROCESS_GROUP +
        # CREATE_BREAKAWAY_FROM_JOB lets us attach a fresh Job Object below (otherwise the
        # child inherits the parent's job and AssignProcessToJobObject may fail).
        popen_kwargs: dict = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
            )
        else:
            popen_kwargs["start_new_session"] = True
            popen_kwargs["preexec_fn"] = _set_pdeathsig  # noqa: PLW1509 - module-level fn

        cmd = command or [sys.executable, "-m", "harness.main"]
        self._proc = subprocess.Popen(  # noqa: S603
            cmd,
            env=env,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd(),
            **popen_kwargs,
        )
        self.pid = self._proc.pid
        self.started_at = datetime.now(tz=UTC)
        self.status = "running"

        # Windows: attach to a Job Object with KILL_ON_JOB_CLOSE so the harness dies when the
        # auditor process dies (even on SIGKILL - the Windows kernel closes our last handle
        # and the job mechanism fires). Best-effort: degrades to "no kill on parent" if the
        # process can't be attached (e.g. nested-job environments without breakaway).
        if sys.platform == "win32":
            try:
                from auditor.enforcement import get_enforcer

                enforcer = get_enforcer()
                # Only the Windows enforcer has this method; on other platforms the cgroup
                # enforcer doesn't, and we never reach this branch.
                ok = enforcer.create_job_for_spawned_process(self.run_id, self.pid)  # type: ignore[attr-defined]
                if not ok:
                    log.warning(
                        "harness_runner.job_attach_failed",
                        run_id=self.run_id,
                        pid=self.pid,
                    )
            except Exception as exc:  # noqa: BLE001 - never block start over enforcer setup
                log.warning(
                    "harness_runner.enforcer_setup_failed",
                    run_id=self.run_id,
                    error=str(exc),
                )

        # Reaper thread - blocks on wait(), updates state on exit, then exits itself. Daemon
        # so it dies with the auditor process. The reaper is the SOLE writer for ``status``,
        # ``exit_code``, ``ended_at``, and the log FD close - no race with API readers.
        self._reaper = threading.Thread(
            target=self._reap,
            name=f"harness-reap-{self.run_id[:8]}",
            daemon=True,
        )
        self._reaper.start()

        with _LIVE_RUNS_LOCK:
            _LIVE_RUNS[self.run_id] = self

        log.info(
            "harness_runner.started",
            run_id=self.run_id,
            tenant_id=str(self.tenant_id),
            pid=self.pid,
            log_path=str(self.log_path),
        )
        return self

    # ----- lifecycle -----

    def _reap(self) -> None:
        """Block on the child, then close the log handle and finalize status."""
        proc = self._proc
        if proc is None:  # pragma: no cover - start() guarantees this is set before reaper
            return
        try:
            code = proc.wait()
        except Exception as exc:  # noqa: BLE001 - log and finalize as exited(-1)
            log.error("harness_runner.wait_failed", run_id=self.run_id, error=str(exc))
            code = -1
        self.exit_code = code
        self.ended_at = datetime.now(tz=UTC)
        self.status = "completed" if code == 0 else f"exited({code})"
        # Close the log handle. Try/except so a flaky filesystem can't crash the reaper.
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "harness_runner.log_close_failed",
                    run_id=self.run_id,
                    error=str(exc),
                )
        log.info(
            "harness_runner.completed",
            run_id=self.run_id,
            pid=self.pid,
            exit_code=code,
            status=self.status,
        )

    def terminate(self, timeout: float = 5.0) -> None:
        """Politely ask the harness to exit (SIGTERM / WM_CLOSE), escalate to kill on timeout."""
        if self._proc is None or self._proc.poll() is not None:
            return
        try:
            self._proc.terminate()
        except Exception as exc:  # noqa: BLE001
            log.warning("harness_runner.terminate_failed", run_id=self.run_id, error=str(exc))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                return
            time.sleep(0.05)
        self.kill()

    def kill(self) -> None:
        """Immediate kill. Reaper handles cleanup."""
        if self._proc is None:
            return
        try:
            self._proc.kill()
        except Exception as exc:  # noqa: BLE001
            log.warning("harness_runner.kill_failed", run_id=self.run_id, error=str(exc))


# ─── Registry helpers + atexit ─────────────────────────────────────────────


def get_run(run_id: str) -> HarnessRun | None:
    """Look up a HarnessRun by run_id. Returns None if not in the live registry."""
    with _LIVE_RUNS_LOCK:
        return _LIVE_RUNS.get(run_id)


def _sweep_expired_runs() -> None:
    """Drop registry entries for runs that completed more than TTL ago. Bounded growth."""
    now = time.time()
    with _LIVE_RUNS_LOCK:
        expired = [
            run_id
            for run_id, run in _LIVE_RUNS.items()
            if run.ended_at is not None
            and (now - run.ended_at.timestamp()) > _REGISTRY_TTL_SECONDS
        ]
        for run_id in expired:
            _LIVE_RUNS.pop(run_id, None)


def _terminate_all_live_runs() -> None:
    """atexit hook: ask every live harness to exit on clean auditor shutdown.

    This is the **clean shutdown** layer. The SIGKILL case (auditor dies without atexit
    firing) is covered by the kernel mechanisms: PR_SET_PDEATHSIG on Linux,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE on Windows.
    """
    with _LIVE_RUNS_LOCK:
        runs = list(_LIVE_RUNS.values())
    for run in runs:
        try:
            run.terminate(timeout=2.0)
        except Exception:  # noqa: BLE001,S110 - best-effort during shutdown
            pass


atexit.register(_terminate_all_live_runs)


__all__ = [
    "HarnessRun",
    "build_child_env",
    "get_run",
]
