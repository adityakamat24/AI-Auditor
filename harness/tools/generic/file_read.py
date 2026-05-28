"""Generic tool: read a file (PRD §9.7).

Sandboxed read: only paths resolving inside ``./data/sandbox`` are permitted; anything else returns an
error and reads nothing. The voluntary counterpart the auditor correlates against involuntary ``openat``
events (channel divergence).
"""

from __future__ import annotations

from pathlib import Path

from harness.telemetry.decorators import instrumented_tool

_SANDBOX = Path("./data/sandbox").resolve()


@instrumented_tool("file_read")
async def file_read(path: str) -> dict:
    """Read a text file from the sandbox directory and return its contents."""
    target = (_SANDBOX / path).resolve()
    if not target.is_relative_to(_SANDBOX):
        return {"error": "path outside sandbox"}
    content = target.read_text(encoding="utf-8") if target.is_file() else ""
    return {"path": path, "content": content}


__all__ = ["file_read"]
