"""Generic tool: execute a shell command (PRD §9.7).

DEFENSIVE STUB. v1 NEVER runs a real shell: the body returns a policy-blocked error and the inline gate
denies it as well (no declared purpose). Present only so adversarial scenarios can attempt the
highest-risk generic tool and observe it being blocked (correlated against involuntary ``execve``, ASI05).
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("exec_shell")
async def exec_shell(cmd: str) -> dict:
    """Execute a shell command and return its output (disabled in v1; blocked by policy)."""
    return {"error": "exec_shell is disabled in v1; blocked by policy", "cmd": cmd}


__all__ = ["exec_shell"]
