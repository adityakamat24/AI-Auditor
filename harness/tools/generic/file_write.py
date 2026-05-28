"""Generic tool: write a file (PRD §9.7).

Sandboxed write: only paths resolving inside ``./data/sandbox`` are permitted; anything else returns an
error and writes nothing. The voluntary counterpart the auditor correlates against involuntary ``openat``
events.
"""

from __future__ import annotations

from pathlib import Path

from harness.telemetry.decorators import instrumented_tool

_SANDBOX = Path("./data/sandbox").resolve()
# Match file_read - strip a leading ``data/sandbox/`` (or ``sandbox/``) prefix so a path the agent
# echoes from the user's prompt resolves to the right target instead of nesting inside the sandbox.
_PREFIX_STRIPS = ("./data/sandbox/", "data/sandbox/", "/data/sandbox/", "sandbox/", "./sandbox/")


def _normalize(path: str) -> str:
    p = path.lstrip("/").lstrip("./")
    for prefix in _PREFIX_STRIPS:
        if p.startswith(prefix.lstrip("/").lstrip("./")):
            return p[len(prefix.lstrip("/").lstrip("./")):]
    return p


@instrumented_tool("file_write")
async def file_write(path: str, content: str = "") -> dict:
    """Write text content to a file inside the sandbox directory and return the bytes written."""
    target = (_SANDBOX / _normalize(path)).resolve()
    if not target.is_relative_to(_SANDBOX):
        return {"error": "path outside sandbox"}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": path, "written": len(content)}


__all__ = ["file_write"]
