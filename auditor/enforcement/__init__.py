"""Enforcement backstop (PRD §9.5) — pause/resume/abort a misbehaving run.

Two layers: the cooperative IPC response (the SDK obeys a DENY — primary, cross-platform) and the
OS-level backstop for a compromised harness (Windows Job Object + process suspend; Linux cgroup freezer
+ seccomp). All implement the :class:`Enforcer` ABC. ``get_enforcer`` selects the platform backstop.
"""

from __future__ import annotations

import sys

from auditor.enforcement.base import Enforcer

# Process-wide singleton: one OS-level enforcer owns the run_id→pid registry for this process, so a run
# paused on a critical flag (HITL router) can be resumed/aborted by the HITL decision route — same
# registry. Without this, each get_enforcer() call would start an empty registry and resume would no-op.
_enforcer: Enforcer | None = None


def get_enforcer() -> Enforcer:
    """Return the process-wide platform OS-level enforcement backstop (instantiated once)."""
    global _enforcer
    if _enforcer is None:
        if sys.platform == "win32":
            from auditor.enforcement.windows_jobobject import WindowsJobObjectEnforcer

            _enforcer = WindowsJobObjectEnforcer()
        elif sys.platform.startswith("linux"):
            from auditor.enforcement.cgroup import CgroupEnforcer

            _enforcer = CgroupEnforcer()
        else:
            raise RuntimeError(f"no enforcement backstop for platform {sys.platform!r}")
    return _enforcer


def reset_enforcer() -> None:
    """Drop the cached enforcer (tests only)."""
    global _enforcer
    _enforcer = None


__all__ = ["Enforcer", "get_enforcer", "reset_enforcer"]
