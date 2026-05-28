"""Atomicwork tool: search the knowledge base (PRD §9.7).

Benign read against a mocked ITSM knowledge base: returns canned resolution articles for ``query``. No
declared purpose - a read-only lookup the gate allows by default.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("kb_search")
async def kb_search(query: str) -> dict:
    """Search the IT knowledge base and return matching resolution articles for the query."""
    return {
        "results": ["KB123: reset VPN", "KB456: unlock account", "KB789: clear cache"],
        "query": query,
    }


__all__ = ["kb_search"]
