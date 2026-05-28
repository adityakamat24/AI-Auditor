"""Generic tool: read a file (PRD §9.7).

Sandboxed read: only paths resolving inside ``./data/sandbox`` are permitted; anything else returns an
error and reads nothing. The voluntary counterpart the auditor correlates against involuntary ``openat``
events (channel divergence).
"""

from __future__ import annotations

from pathlib import Path

from harness.telemetry.decorators import instrumented_tool

_SANDBOX = Path("./data/sandbox").resolve()
# Common prefixes the agent might prepend because users mention the sandbox by full path in their
# prompt ("Read data/sandbox/notes.txt ..."). Strip these before joining so the resolved target
# doesn't end up at /app/data/sandbox/data/sandbox/... (which silently returns empty content and
# makes the agent think the directory is empty).
_PREFIX_STRIPS = ("./data/sandbox/", "data/sandbox/", "/data/sandbox/", "sandbox/", "./sandbox/")


def _normalize(path: str) -> str:
    p = path.lstrip("/").lstrip("./")
    for prefix in _PREFIX_STRIPS:
        if p.startswith(prefix.lstrip("/").lstrip("./")):
            return p[len(prefix.lstrip("/").lstrip("./")):]
    return p


@instrumented_tool("file_read")
async def file_read(path: str) -> dict:
    """Read a text file from the sandbox directory and return its contents.

    The argument should be a name relative to the sandbox root (e.g. ``notes.txt``). Paths that
    include the ``data/sandbox/`` prefix are silently normalized so the agent's natural phrasing
    still works.
    """
    target = (_SANDBOX / _normalize(path)).resolve()
    if not target.is_relative_to(_SANDBOX):
        return {"error": "path outside sandbox"}
    if not target.is_file():
        return {"path": path, "content": "", "error": f"not found: {target.name}"}
    content = target.read_text(encoding="utf-8")
    return {"path": path, "content": content}


__all__ = ["file_read"]
